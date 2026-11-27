//! Attachment uploads, downloads and local file storage.

use super::{
    Engine, HISTORY_SHOWN, Inner, MAX_FILE_SIZE, NOT_SIGNED_IN_HERE, POLL_CHUNK_MAX,
    POLL_CHUNK_MIN, RETRY_MAX, RETRY_MIN, STALLED, VaultStore, WAITS_SIGN_IN, attachment_key_hash,
    origin, records, same_server,
};
use crate::content::{AttachmentPointer, Content, Kind};
use crate::preview;
use crate::preview::Sort;
use crate::state::{Attachment, Body, Delivery, FileView, Link, Opening, UploadState, UploadView};
use crate::transport::{Connect, Fetch, Progress};
use crate::util::{describe, js_error, size_u64, sleep};
use crate::vault::{
    OutgoingRecord, PendingUpload, UPLOAD_STATE_ANNOUNCED, UPLOAD_STATE_STARTED,
    UPLOAD_STATE_WAITING,
};
use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use leptos::task::spawn_local;
use session::attachment::{CHUNK_SIZE, Upload};
use session::{ErrorKind, PublicKey, attachment};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

/// Local plaintext file source for an active upload or cached sender preview.
#[derive(Clone)]
pub(super) enum ChunkSource {
    File(web_sys::File),
    #[cfg(all(test, not(target_arch = "wasm32")))]
    Bytes {
        name: String,
        mime: String,
        data: Arc<Vec<u8>>,
    },
}

impl ChunkSource {
    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(super) fn from_bytes(
        name: impl Into<String>,
        mime: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        Self::Bytes {
            name: name.into(),
            mime: mime.into(),
            data: Arc::new(data.into()),
        }
    }

    pub(super) fn name(&self) -> String {
        match self {
            Self::File(file) => file.name(),
            #[cfg(all(test, not(target_arch = "wasm32")))]
            Self::Bytes { name, .. } => name.clone(),
        }
    }

    pub(super) fn mime(&self) -> String {
        match self {
            Self::File(file) => file.type_(),
            #[cfg(all(test, not(target_arch = "wasm32")))]
            Self::Bytes { mime, .. } => mime.clone(),
        }
    }

    pub(super) fn size(&self) -> u64 {
        match self {
            Self::File(file) => file.size() as u64,
            #[cfg(all(test, not(target_arch = "wasm32")))]
            Self::Bytes { data, .. } => data.len() as u64,
        }
    }

    pub(super) async fn read_all(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::File(file) => {
                let buffer = JsFuture::from(file.array_buffer())
                    .await
                    .map_err(|e| format!("Cannot read {}: {}", file.name(), js_error(e)))?;
                Ok(js_sys::Uint8Array::new(&buffer).to_vec())
            }
            #[cfg(all(test, not(target_arch = "wasm32")))]
            Self::Bytes { data, .. } => Ok((**data).clone()),
        }
    }
}

/// Network deletion job prepared under `Engine::inner` and executed outside the lock so slow
/// server deletes never freeze chat/streaming/UI.
pub(super) struct ServerDeleteJob {
    server: String,
    id: [u8; 16],
    history_index: Option<u64>,
    name: String,
    kind: ServerDeleteKind,
}

enum ServerDeleteKind {
    CancelUpload(Upload),
    DeleteCompleted(Zeroizing<[u8; attachment::KEY_LENGTH]>),
}

/// Verified prefix hash, cached plaintext chunks, and per-chunk SHA-256 digests for resuming an
/// interrupted upload without re-reading already-encrypted chunks from a mutable `File` handle.
pub(super) struct VerifiedResume {
    pub(super) hasher: Sha256,
    pub(super) verified_chunks: HashMap<u32, Zeroizing<Vec<u8>>>,
    pub(super) digests: HashMap<u32, [u8; 32]>,
}

impl VerifiedResume {
    pub(super) fn fresh() -> Self {
        Self {
            hasher: Sha256::new(),
            verified_chunks: HashMap::new(),
            digests: HashMap::new(),
        }
    }
}

/// Pure, incrementally-fed verifier for resumed upload prefixes (`0..pending.encrypted`),
/// confirming both `prefix_hash` and `sealed_chunk_hash` while retaining the exact verified bytes
/// for `pending.uploaded..pending.encrypted`.
pub(super) struct ResumeVerifier {
    uploaded: u32,
    encrypted: u32,
    next_index: u32,
    size: u64,
    chunks: u32,
    expected_prefix_hash: Zeroizing<Vec<u8>>,
    expected_sealed_chunk_hash: Zeroizing<Vec<u8>>,
    name: String,
    hasher: Sha256,
    verified_chunks: HashMap<u32, Zeroizing<Vec<u8>>>,
    digests: HashMap<u32, [u8; 32]>,
}

impl ResumeVerifier {
    pub(super) fn new(pending: &PendingUpload, file_size: u64) -> Result<Self, String> {
        let other = || format!("that is not {}, or it changed", pending.name);
        if file_size != pending.size {
            return Err(other());
        }
        let chunks = u32::try_from(attachment::chunk_count(pending.size)).map_err(|_| other())?;
        if pending.uploaded > pending.encrypted || pending.encrypted > chunks {
            return Err(format!("the upload of {} is corrupt", pending.name));
        }
        if pending.encrypted > pending.uploaded
            && !pending.sealed_chunk_hash.is_empty()
            && pending.sealed_chunk_hash.len() != 32
        {
            return Err(format!("the upload of {} is corrupt", pending.name));
        }
        Ok(Self {
            uploaded: pending.uploaded,
            encrypted: pending.encrypted,
            next_index: 0,
            size: pending.size,
            chunks,
            expected_prefix_hash: Zeroizing::new(pending.prefix_hash.clone()),
            expected_sealed_chunk_hash: Zeroizing::new(pending.sealed_chunk_hash.clone()),
            name: pending.name.clone(),
            hasher: Sha256::new(),
            verified_chunks: HashMap::new(),
            digests: HashMap::new(),
        })
    }

    pub(super) fn push_chunk(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        let other = || format!("that is not {}, or it changed", self.name);
        let index = self.next_index;
        if index >= self.encrypted {
            return Err(other());
        }
        let expected_len = expected_chunk_len(self.size, index, self.chunks).ok_or_else(other)?;
        if bytes.len() != expected_len {
            return Err(other());
        }
        self.hasher.update(&bytes);
        if index >= self.uploaded {
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            if index == self.uploaded
                && !self.expected_sealed_chunk_hash.is_empty()
                && digest.as_slice() != self.expected_sealed_chunk_hash.as_slice()
            {
                return Err(other());
            }
            self.digests.insert(index, digest);
            self.verified_chunks.insert(index, Zeroizing::new(bytes));
        }
        self.next_index += 1;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<VerifiedResume, String> {
        let other = || format!("that is not {}, or it changed", self.name);
        if self.next_index != self.encrypted {
            return Err(other());
        }
        if self.hasher.clone().finalize().as_slice() != self.expected_prefix_hash.as_slice() {
            return Err(other());
        }
        Ok(VerifiedResume {
            hasher: self.hasher,
            verified_chunks: self.verified_chunks,
            digests: self.digests,
        })
    }
}

/// Expected plaintext byte length of chunk `index` for an attachment of `total_size` bytes split
/// into `chunks` chunks (`CHUNK_SIZE` for every non-last chunk, remainder for the last).
pub(super) fn expected_chunk_len(total_size: u64, index: u32, chunks: u32) -> Option<usize> {
    if chunks == 0 || index >= chunks {
        return None;
    }
    if index + 1 < chunks {
        let end = u64::from(index + 1).checked_mul(CHUNK_SIZE as u64)?;
        (end <= total_size).then_some(CHUNK_SIZE)
    } else {
        let start = u64::from(index).checked_mul(CHUNK_SIZE as u64)?;
        let rem = total_size.checked_sub(start)?;
        (rem <= CHUNK_SIZE as u64).then_some(rem as usize)
    }
}

/// Copy `bytes` directly into a `Zeroizing<[u8; N]>` without creating an unzeroized stack array.
fn copy_zeroizing_array<const N: usize>(bytes: &[u8]) -> Option<Zeroizing<[u8; N]>> {
    if bytes.len() != N {
        return None;
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(bytes);
    Some(out)
}

/// Error fetching an attachment chunk, preserving HTTP 404 (`NotFound`) so callers can mark the
/// attachment gone from the server.
pub(super) enum FetchError {
    NotFound(String),
    Other(String),
}

/// Error announcing a newly started attachment in chat history, distinguishing pre-send failure
/// (safe to cancel on the server) from post-send vault save failure (where the peer may already
/// hold the attachment pointer).
enum AnnounceError {
    NotSent(String),
    SaveAfterSend {
        error: String,
        pending: Box<PendingUpload>,
    },
}

impl AnnounceError {
    fn into_message(self) -> String {
        match self {
            Self::NotSent(msg) | Self::SaveAfterSend { error: msg, .. } => msg,
        }
    }
}

impl FetchError {
    fn into_message(self) -> String {
        match self {
            Self::NotFound(msg) | Self::Other(msg) => msg,
        }
    }
}

/// What fetching an attachment's chunks takes, see [`Engine::chunk`].
pub(super) struct Fetching {
    /// The chat it is in.
    pub(super) peer: PublicKey,
    /// Its entry in the history.
    pub(super) index: u64,
    pub(super) id: [u8; 16],
    pub(super) key: Zeroizing<[u8; attachment::KEY_LENGTH]>,
    pub(super) key_hash: [u8; 32],
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) chunks: u32,
    /// How far this client's own upload of it got, if it is unfinished, its file gone with the
    /// page: what the server lacks only comes once the file is chosen again.
    pub(super) unfinished: Option<u32>,
    pub(super) attachments: Connect,
}

/// Who waits for an attachment.
#[derive(Clone, Copy)]
pub(super) enum Waiter<'a> {
    /// The viewer, for the preview request identified by its monotonic token, until it closes or
    /// goes on to another request.
    Viewer(u64),
    /// The chat, showing it in place, while this says it does.
    Chat(&'a dyn Fn() -> bool),
}

impl<V: VaultStore> Engine<V> {
    /// Whether upload `id` was cancelled (or its chat deleted) on this page.
    pub(super) fn is_cancelled(&self, id: &[u8; 16]) -> bool {
        self.uploads.is_cancelled(id)
    }

    /// Send `peer` an attachment of `file`, then upload it: the peer can download it meanwhile,
    /// and what was sent after it goes without waiting for the upload. Its chunks are kept here
    /// too, so it opens without the server. Each chunk is read as its turn comes, and the upload
    /// is kept in the vault as it goes, so that it can go on after the page goes.
    pub(super) async fn send_attachment(
        self: &Rc<Self>,
        peer: PublicKey,
        file: ChunkSource,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let size = file.size();
        let (started, signs_in_here, server) = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            if contact.state.request {
                return Err("accept the request first".into());
            }
            if contact.state.quarantined {
                return Err("approve classical encryption or upgrade to post-quantum first".into());
            }
            let server = inner.server.clone();
            let started = inner
                .client
                .start_upload(&Fetch::client(&server), size)
                .await;
            (started, same_server(&server, &origin()), server)
        };
        if !self.is_live(vgen) {
            if let Ok(upload) = started {
                let _ = upload.cancel(&Fetch::client(&server)).await;
            }
            return Err("locked".into());
        }
        let upload = match started {
            Ok(upload) => upload,
            // The server keeps attachments only for those signed in to it: its message takes its
            // place in the chat, and waits, with what is sent after it, until this browser is.
            Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => {
                self.wait_for_sign_in(peer, file).await?;
                if self.is_live(vgen) {
                    self.ask_sign_in();
                }
                return Ok(());
            }
            // This page cannot sign in to the server, so the file never would go.
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                return Err(format!(
                    "{} could not be sent: {NOT_SIGNED_IN_HERE}",
                    file.name()
                ));
            }
            Err(e) => {
                // Report attachment 404/Unimplemented locally without tripping global update_required.
                return Err(describe(&e));
            }
        };
        let pending = PendingUpload {
            id: upload.id().to_vec(),
            token: upload.token().to_vec(),
            key: upload.key().to_vec(),
            expires: upload.expires().unwrap_or_default(),
            name: file.name(),
            mime: file.mime(),
            size,
            uploaded: 0,
            encrypted: 0,
            prefix_hash: Sha256::digest([]).to_vec(),
            announced: false,
            history_index: 0,
            upload_state: UPLOAD_STATE_STARTED,
            sealed_chunk_hash: Vec::new(),
        };
        if let Err(e) = self.save_upload(&peer, &pending).await {
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Err(e);
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.uploads.insert_file(
            (peer, *upload.id(), attachment_key_hash(upload.key())),
            file.clone(),
        );
        let pending = match self.announce(&peer, pending).await {
            Ok(Some(pending)) => pending,
            Ok(None) => return Ok(()),
            Err(AnnounceError::NotSent(e)) => {
                self.uploads.mark_cancelled(*upload.id());
                self.remove_attachment_caches(&peer, upload.id());
                {
                    let guard = self.lock_inner().await;
                    if let Some(inner) = guard.as_ref() {
                        let _ = inner.vault.forget_upload(&peer, upload.id()).await;
                    }
                }
                let _ = upload.cancel(&Fetch::client(&server)).await;
                return Err(e);
            }
            Err(AnnounceError::SaveAfterSend { error, pending }) => {
                let keep = {
                    let guard = self.lock_inner().await;
                    self.is_live(vgen)
                        && guard
                            .as_ref()
                            .is_some_and(|inner| self.may_keep(inner, &peer, upload.id()))
                };
                if keep {
                    self.show_upload(&peer, &pending, UploadState::Paused(error.clone()));
                } else {
                    self.uploads.mark_cancelled(*upload.id());
                    self.remove_attachment_caches(&peer, upload.id());
                    let _ = upload.cancel(&Fetch::client(&server)).await;
                }
                return Err(error);
            }
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        // A new upload, which nothing else runs.
        self.uploads.start_running(*upload.id());
        self.show_upload(&peer, &pending, UploadState::Running);
        let engine = self.clone();
        #[cfg(target_arch = "wasm32")]
        spawn_local(async move {
            if let Err(e) = engine
                .run_upload(peer, pending, file, VerifiedResume::fresh())
                .await
                && engine.is_live(vgen)
            {
                engine.ui.notify(e);
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        if let Err(e) = engine
            .run_upload(peer, pending, file, VerifiedResume::fresh())
            .await
            && engine.is_live(vgen)
        {
            engine.ui.notify(e);
        }
        Ok(())
    }

    /// Keep `file`, to `peer`, until this browser signs in to the server, which takes no
    /// attachment before: its message takes its place in the chat at once, waiting, and what is
    /// sent after it waits for it, see `flush`. Its upload, kept under an ID of this client's,
    /// starts once signed in, see [`start_waiting`](Self::start_waiting); after the page goes,
    /// once the file is chosen again.
    pub(super) async fn wait_for_sign_in(
        &self,
        peer: PublicKey,
        file: ChunkSource,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| e.to_string())?;
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let inner = guard.as_mut().ok_or("locked")?;
        let contact = inner.contact(&peer).ok_or("no such chat")?;
        let waiting = PendingUpload {
            id: id.to_vec(),
            name: file.name(),
            mime: file.mime(),
            size: file.size(),
            announced: false,
            history_index: contact.state.history_len,
            token: Vec::new(),
            key: Vec::new(),
            uploaded: 0,
            encrypted: 0,
            prefix_hash: Vec::new(),
            expires: 0,
            upload_state: UPLOAD_STATE_WAITING,
            sealed_chunk_hash: Vec::new(),
        };
        // Kept first, so that no message waits for an upload that is not kept.
        inner
            .vault
            .save_upload(&peer, &waiting)
            .await
            .map_err(|e| describe(&e))?;
        let pointer = AttachmentPointer {
            id: vec![],
            key: vec![],
            size: waiting.size,
            name: waiting.name.clone(),
            mime: waiting.mime.clone(),
            expires: 0,
        };
        let view = match inner.add(&peer, Kind::Attachment(pointer), true).await {
            Ok(view) => view,
            Err(e) => {
                let _ = inner.vault.forget_upload(&peer, &id).await;
                return Err(e);
            }
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.show_new(inner, &peer, vec![view]);
        self.refresh_contacts(inner);
        drop(guard);
        self.uploads
            .insert_file((peer, id, attachment_key_hash(&[])), file);
        self.show_upload(
            &peer,
            &waiting,
            UploadState::Paused(WAITS_SIGN_IN.to_string()),
        );
        self.hold(&peer, waiting.history_index);
        Ok(())
    }

    /// Start the uploads that waited for this browser to sign in, whose files are still here.
    pub(super) async fn start_waiting_uploads(self: &Rc<Self>) {
        let vgen = self.vault_gen();
        let waiting = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return;
            }
            let Some(inner) = guard.as_ref() else {
                return;
            };
            match inner.vault.uploads(None).await {
                Ok(uploads) => uploads,
                Err(e) => {
                    if self.is_live(vgen) {
                        self.ui.notify(describe(&e));
                    }
                    return;
                }
            }
        };
        for (peer, pending) in waiting.into_iter().filter(|(_, p)| !p.started()) {
            if !self.is_live(vgen) {
                return;
            }
            let Ok(id) = <[u8; 16]>::try_from(pending.id.as_slice()) else {
                continue;
            };
            if self.is_cancelled(&id) || self.uploads.is_running(&id) {
                continue;
            }
            let key = (peer, id, attachment_key_hash(&pending.key));
            let Some(file) = self.uploads.get_file(&key) else {
                // Re-check under the lock so an upload already promoted by a concurrent
                // `resume_upload` or dropped by `SealOutcome::Failed` is never resurrected.
                let still_waiting = {
                    let guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        return;
                    }
                    let Some(inner) = guard.as_ref() else {
                        return;
                    };
                    if self.is_cancelled(&id) || self.uploads.is_running(&id) {
                        false
                    } else {
                        inner
                            .vault
                            .upload(&peer, &id)
                            .await
                            .ok()
                            .flatten()
                            .is_some_and(|p| {
                                !p.started()
                                    && inner.contacts.iter().any(|c| {
                                        c.peer == peer
                                            && c.state.outbox.iter().any(|o| {
                                                o.history_index == p.history_index
                                                    && o.awaits_upload
                                            })
                                    })
                            })
                    }
                };
                if still_waiting && self.is_live(vgen) {
                    self.show_upload(
                        &peer,
                        &pending,
                        UploadState::Paused("choose the file again to upload".to_string()),
                    );
                }
                continue;
            };
            if !self.uploads.start_running(id) {
                continue;
            }
            let running_guard = scopeguard::guard(id, |id| {
                self.uploads.stop_running(&id);
            });
            let result = self.start_waiting(peer, id, file).await;
            drop(running_guard);
            if let Err(e) = result
                && self.is_live(vgen)
            {
                self.ui.notify(e);
            }
        }
    }

    /// Start the upload `waiting`, to `peer`, of `file`, which waited for this browser to sign
    /// in: its message, which kept its place in the chat, gets the attachment and goes, with
    /// what waited for it, and the upload runs. Refused again, it waits again.
    pub(super) async fn start_waiting(
        self: &Rc<Self>,
        peer: PublicKey,
        waiting: [u8; 16],
        file: ChunkSource,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) || self.is_cancelled(&waiting) {
            return Ok(());
        }
        let inner = guard.as_mut().ok_or("locked")?;
        let Some(kept) = inner
            .vault
            .upload(&peer, &waiting)
            .await
            .map_err(|e| describe(&e))?
            .filter(|pending| !pending.started())
        else {
            return Ok(());
        };
        if file.size() != kept.size {
            return Err(format!("that is not {}, or it changed", kept.name));
        }
        // Its message still waits for it, unless this record outlived its start, as forgetting
        // it failed: that message has its attachment, and a second upload must not replace it.
        let awaited = inner.contact(&peer).is_some_and(|contact| {
            contact.state.outbox.iter().any(|outgoing| {
                outgoing.history_index == kept.history_index && outgoing.awaits_upload
            })
        });
        if !awaited {
            self.release(&peer, kept.history_index);
            self.remove_attachment_caches(&peer, &waiting);
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|upload| upload.id != waiting));
            return inner
                .vault
                .forget_upload(&peer, &waiting)
                .await
                .map_err(|e| describe(&e));
        }
        // Validate the waiting message and contact BEFORE allocating a server upload so a missing
        // history entry cannot orphan a server upload or a `started = true` vault record.
        let mut entry = inner
            .vault
            .entry(&peer, kept.history_index)
            .await
            .map_err(|e| describe(&e))?
            .ok_or("its message is gone")?;
        if inner.contact(&peer).is_none() {
            return Err("no such chat".into());
        }
        if self.is_cancelled(&waiting) {
            return Ok(());
        }
        let started = inner
            .client
            .start_upload(&Fetch::client(&inner.server), kept.size)
            .await;
        let upload = match started {
            Ok(upload) => upload,
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                drop(guard);
                if !self.is_live(vgen) || self.is_cancelled(&waiting) {
                    return Ok(());
                }
                self.uploads
                    .insert_file((peer, waiting, attachment_key_hash(&kept.key)), file);
                self.show_upload(&peer, &kept, UploadState::Paused(WAITS_SIGN_IN.to_string()));
                self.ask_sign_in();
                return Ok(());
            }
            Err(e) => {
                if !self.is_live(vgen) || self.is_cancelled(&waiting) {
                    return Ok(());
                }
                // Report attachment 404/Unimplemented locally without tripping global update_required.
                return Err(describe(&e));
            }
        };
        let server = inner.server.clone();
        // Cancelled meanwhile: the server forgets it too (outside the lock), and cancelling fails
        // its message.
        if !self.is_live(vgen) || self.is_cancelled(&waiting) {
            drop(guard);
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Ok(());
        }
        let pointer = AttachmentPointer {
            id: upload.id().to_vec(),
            key: upload.key().to_vec(),
            size: kept.size,
            name: kept.name.clone(),
            mime: kept.mime.clone(),
            expires: upload.expires().unwrap_or_default(),
        };
        let pending = PendingUpload {
            id: upload.id().to_vec(),
            token: upload.token().to_vec(),
            key: upload.key().to_vec(),
            prefix_hash: Sha256::digest([]).to_vec(),
            history_index: kept.history_index,
            expires: upload.expires().unwrap_or_default(),
            name: kept.name.clone(),
            mime: kept.mime.clone(),
            size: kept.size,
            uploaded: kept.uploaded,
            encrypted: kept.encrypted,
            announced: true,
            upload_state: UPLOAD_STATE_ANNOUNCED,
            sealed_chunk_hash: Vec::new(),
        };
        let content = Kind::Attachment(pointer);
        let content_bytes = content.to_bytes();
        let content_digest = crate::vault::content_kind_digest(&content_bytes);
        let record = OutgoingRecord::unsealed(content_bytes);
        entry.content = Some(Content {
            kind: Some(content),
            ..entry.content.unwrap_or_default()
        });
        let mut changed = [(kept.history_index, entry)];
        // Atomically commit the new server-assigned `PendingUpload`, delete the old waiting
        // placeholder record, update the `HistoryEntry` and `OutgoingRecord`, and save `AppState`
        // in ONE single IndexedDB transaction so a crash can never orphan an upload from its chat
        // pointer.
        let promoted = inner
            .with_contact_tx(&peer, async |inner| {
                let contact = inner
                    .contact(&peer)
                    .ok_or_else(|| "no such chat".to_string())?;
                for outgoing in &mut contact.state.outbox {
                    if outgoing.history_index == kept.history_index {
                        outgoing.awaits_upload = false;
                        outgoing.content_digest = content_digest.clone();
                    }
                }
                inner
                    .promote_upload_with(
                        &peer,
                        &waiting,
                        &pending,
                        &records(&peer, &changed),
                        &[(peer, kept.history_index, Some(record))],
                    )
                    .await
                    .map_err(|e| describe(&e))
            })
            .await;
        if let Err(e) = promoted {
            drop(guard);
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Err(e);
        }
        // Cancelled while it started, which found nothing left to cancel: it goes no further,
        // and its message reverts to an un-uploaded failed attachment without publishing the
        // cancelled pointer ID to the UI.
        if self.is_cancelled(&waiting) {
            self.uploads.mark_cancelled(*upload.id());
            self.remove_attachment_caches(&peer, &waiting);
            self.remove_attachment_caches(&peer, upload.id());
            let _ = inner.vault.forget_upload(&peer, upload.id()).await;
            if let Some(Kind::Attachment(pointer)) = changed[0]
                .1
                .content
                .as_mut()
                .and_then(|content| content.kind.as_mut())
            {
                pointer.id.clear();
                pointer.key.clear();
                pointer.expires = 0;
            }
            changed[0].1.set_delivery(Delivery::Failed);
            let reverted = inner
                .with_contact_tx(&peer, async |inner| {
                    let contact = inner
                        .contact(&peer)
                        .ok_or_else(|| "no such chat".to_string())?;
                    contact
                        .state
                        .outbox
                        .retain(|outgoing| outgoing.history_index != kept.history_index);
                    inner
                        .save_with(
                            &records(&peer, &changed),
                            &[(peer, kept.history_index, None)],
                        )
                        .await
                        .map_err(|e| describe(&e))
                })
                .await;
            if reverted.is_ok() {
                self.release(&peer, kept.history_index);
                self.show_changes(inner, &peer, &changed);
            }
            drop(guard);
            let _ = upload.cancel(&Fetch::client(&server)).await;
            reverted?;
            if let Err(e) = self.flush(&peer).await {
                self.ui.link.set(Link::Offline(e));
            }
            return Ok(());
        }
        if !self.is_live(vgen) {
            return Ok(());
        }
        self.show_changes(inner, &peer, &changed);
        drop(guard);
        // Under the server's ID and key hash from now on.
        self.remove_attachment_caches(&peer, &waiting);
        self.uploads.insert_file(
            (peer, *upload.id(), attachment_key_hash(upload.key())),
            file.clone(),
        );
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != waiting));
        self.uploads.stop_running(&waiting);
        let new_id = *upload.id();
        self.uploads.start_running(new_id);
        let new_running_guard = scopeguard::guard(new_id, |id| {
            self.uploads.stop_running(&id);
        });
        self.show_upload(&peer, &pending, UploadState::Running);
        self.release(&peer, kept.history_index);
        if let Err(e) = self.flush(&peer).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
        // If `flush` permanently failed or `cancel_held`/`cancel_upload` cancelled the upload
        // while announcing, stop without uploading chunks to R2.
        let cancelled = !self.is_live(vgen) || self.is_cancelled(&new_id);
        let failed_or_cancelled = if cancelled {
            true
        } else {
            let guard = self.lock_inner().await;
            if let Some(inner) = guard.as_ref() {
                inner
                    .vault
                    .entry(&peer, kept.history_index)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|e| e.delivery() == Delivery::Failed)
            } else {
                true
            }
        };
        if failed_or_cancelled {
            drop(new_running_guard);
            if self.is_live(vgen) {
                self.wake();
            }
            return Ok(());
        }
        // Transfer running ownership to the spawned `run_upload` task (which installs its own
        // `scopeguard` immediately).
        let _ = scopeguard::ScopeGuard::into_inner(new_running_guard);
        self.wake();
        let engine = self.clone();
        #[cfg(target_arch = "wasm32")]
        spawn_local(async move {
            if let Err(e) = engine
                .run_upload(peer, pending, file, VerifiedResume::fresh())
                .await
                && engine.is_live(vgen)
            {
                engine.ui.notify(e);
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        if let Err(e) = engine
            .run_upload(peer, pending, file, VerifiedResume::fresh())
            .await
            && engine.is_live(vgen)
        {
            engine.ui.notify(e);
        }
        Ok(())
    }

    /// Send the attachment of `pending` to `peer`, unless sent already, and keep that it was.
    /// Returns `Ok(None)` if the announcement permanently failed or was cancelled during `flush`.
    async fn announce(
        &self,
        peer: &PublicKey,
        mut pending: PendingUpload,
    ) -> Result<Option<PendingUpload>, AnnounceError> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Err(AnnounceError::NotSent("locked".into()));
        }
        if pending.is_announced() {
            return Ok(Some(pending));
        }
        let id_arr = <[u8; 16]>::try_from(pending.id.as_slice()).ok();
        // Hold one lock across scanning history for an already-persisted announcement, checking
        // cancellation/chat deletion, and adding a new outgoing message so a queued `cancel_upload`
        // or `delete(peer)` cannot slip in before `inner.add` and send a deleted attachment.
        let (index, added_new) = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err(AnnounceError::NotSent("locked".into()));
            }
            let Some(inner) = guard.as_mut() else {
                return Err(AnnounceError::NotSent("locked".into()));
            };
            let found = inner
                .find_attachment_entry(peer, None, &pending.id)
                .await
                .map_err(|e| AnnounceError::NotSent(describe(&e)))?
                .filter(|(_, entry)| entry.outgoing)
                .map(|(idx, _)| idx);
            if !self.is_live(vgen) {
                return Err(AnnounceError::NotSent("locked".into()));
            }
            if !self.may_keep(inner, peer, &pending.id) {
                if let Some(id) = id_arr {
                    self.remove_attachment_caches(peer, &id);
                    self.ui
                        .uploads
                        .update(|uploads| uploads.retain(|item| item.id != id));
                }
                return Ok(None);
            }
            match found {
                Some(index) => (index, false),
                None => {
                    let pointer = AttachmentPointer {
                        id: pending.id.clone(),
                        key: pending.key.clone(),
                        size: pending.size,
                        name: pending.name.clone(),
                        mime: pending.mime.clone(),
                        expires: pending.expires,
                    };
                    let view = inner
                        .add(peer, Kind::Attachment(pointer), false)
                        .await
                        .map_err(AnnounceError::NotSent)?;
                    if !self.is_live(vgen) {
                        return Err(AnnounceError::NotSent("locked".into()));
                    }
                    let index = view.index;
                    self.show_new(inner, peer, vec![view]);
                    self.refresh_contacts(inner);
                    (index, true)
                }
            }
        };
        if added_new {
            // Saved, so it goes in a later sync if not now.
            if let Err(e) = self.flush(peer).await
                && self.is_live(vgen)
            {
                self.ui.link.set(Link::Offline(e));
            }
            self.wake();
        }
        // Hold one lock across checking delivery failure, concurrent cancellation/chat deletion,
        // and persisting `announced = true` so a concurrent cancel cannot race into a spurious
        // `"the upload of ... was cancelled"` error toast or mark an offline cancel gone early.
        pending.announced = true;
        pending.upload_state = UPLOAD_STATE_ANNOUNCED;
        pending.history_index = index;
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err(AnnounceError::SaveAfterSend {
                error: "locked".into(),
                pending: Box::new(pending),
            });
        }
        let Some(inner) = guard.as_mut() else {
            return Err(AnnounceError::SaveAfterSend {
                error: "locked".into(),
                pending: Box::new(pending),
            });
        };
        let entry_failed = inner
            .vault
            .entry(peer, index)
            .await
            .ok()
            .flatten()
            .is_some_and(|e| e.delivery() == Delivery::Failed);
        if !self.is_live(vgen) {
            return Err(AnnounceError::SaveAfterSend {
                error: "locked".into(),
                pending: Box::new(pending),
            });
        }
        if entry_failed {
            let jobs = self
                .prepare_cancel_uploads_for_failed(inner, peer, &[index])
                .await;
            drop(guard);
            if self.is_live(vgen) {
                self.finish_server_deletes(peer, jobs).await;
            }
            return Ok(None);
        }
        if !self.may_keep(inner, peer, &pending.id) {
            if let Some(id) = id_arr {
                self.remove_attachment_caches(peer, &id);
                self.ui
                    .uploads
                    .update(|uploads| uploads.retain(|item| item.id != id));
            }
            return Ok(None);
        }
        if let Err(e) = inner.vault.save_upload(peer, &pending).await {
            return Err(AnnounceError::SaveAfterSend {
                error: describe(&e),
                pending: Box::new(pending),
            });
        }
        Ok(Some(pending))
    }

    /// The bytes of the file of the history entry `index` of the chat with `peer`, which are
    /// kept apart from it.
    pub async fn file(&self, peer: PublicKey, index: u64) -> Result<Arc<Vec<u8>>, String> {
        let guard = self.lock_inner().await;
        let inner = guard.as_ref().ok_or("locked")?;
        inner
            .vault
            .file(&peer, index)
            .await
            .map(Arc::new)
            .map_err(|e| describe(&e))
    }

    /// Purge in-memory file and decrypted chunk caches for `(peer, id)`.
    pub(super) fn remove_attachment_caches(&self, peer: &PublicKey, id: &[u8; 16]) {
        self.uploads.remove_attachment_files(peer, id);
        self.media.remove_attachment_chunks(peer, id);
    }

    /// Whether the file of the upload `id` for `peer` is still here, so that it can go on without
    /// the file chosen again.
    pub fn has_file(&self, peer: &PublicKey, id: &[u8; 16]) -> bool {
        self.uploads.has_file(peer, id)
    }

    /// Go on with the upload `id`, in the chat with `peer`: with `file`, chosen again, or else
    /// with the file still here. The file must begin as it did, as far as it may have been
    /// encrypted.
    pub async fn resume_upload(
        self: &Rc<Self>,
        peer: PublicKey,
        id: [u8; 16],
        file: Option<web_sys::File>,
    ) -> Result<(), String> {
        self.resume_upload_source(peer, id, file.map(ChunkSource::File))
            .await
    }

    pub(super) async fn resume_upload_source(
        self: &Rc<Self>,
        peer: PublicKey,
        id: [u8; 16],
        file: Option<ChunkSource>,
    ) -> Result<(), String> {
        // Guard the upload ID in `self.uploads` up front so double-clicking Resume on either a
        // sign-in-held (`!started()`) upload or a started upload cannot race `start_waiting` and
        // surface a spurious `"that upload is gone"` error.
        if self.is_cancelled(&id) || !self.uploads.start_running(id) {
            return Ok(());
        }
        let running_guard = scopeguard::guard(id, |id| {
            self.uploads.stop_running(&id);
        });
        // Look up the pending upload once under the lock, exiting quietly if it was cancelled or
        // forgotten concurrently (e.g. by `cancel_upload`, `SealOutcome::Failed`, or `delete`).
        let vgen = self.vault_gen();
        let pending = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let Some(inner) = guard.as_ref() else {
                return Err("locked".into());
            };
            match inner.vault.upload(&peer, &id).await {
                Ok(Some(pending)) => {
                    if !self.is_live(vgen) || self.is_cancelled(&id) {
                        return Ok(());
                    }
                    pending
                }
                Ok(None) => {
                    if !self.is_live(vgen) || self.is_cancelled(&id) {
                        return Ok(());
                    }
                    return Err("that upload is gone".into());
                }
                Err(e) => return Err(describe(&e)),
            }
        };
        // One that waited for a sign-in starts, its message in its place.
        if !pending.started() {
            let key = (peer, id, attachment_key_hash(&[]));
            let file = file
                .or_else(|| self.uploads.get_file(&key))
                .ok_or("choose the file again")?;
            return self.start_waiting(peer, id, file).await;
        }
        let cache_key = (peer, id, attachment_key_hash(&pending.key));
        let file = file
            .or_else(|| self.uploads.get_file(&cache_key))
            .ok_or("choose the file again")?;
        let resume = match self.check(&peer, &pending, &file).await {
            Ok(resume) => resume,
            Err(e) => {
                if self.is_live(vgen) && !self.is_cancelled(&id) {
                    self.show_upload(&peer, &pending, UploadState::Paused(e.clone()));
                }
                return Err(e);
            }
        };
        // Cancelled while the file was checked: it is not sent.
        if !self.is_live(vgen) || self.is_cancelled(&id) {
            return Ok(());
        }
        self.uploads.insert_file(cache_key, file.clone());
        let before_announce = pending.clone();
        let pending = match self.announce(&peer, pending).await {
            Ok(Some(pending)) => pending,
            Ok(None) => return Ok(()),
            Err(err) => {
                let msg = err.into_message();
                if self.is_live(vgen) && !self.is_cancelled(&id) {
                    self.show_upload(&peer, &before_announce, UploadState::Paused(msg.clone()));
                }
                return Err(msg);
            }
        };
        let result = self.run_upload(peer, pending, file, resume).await;
        drop(running_guard);
        result
    }

    /// Stop the upload `id`, in the chat with `peer`, and forget it. The server deletes what it
    /// has, so the peer finds the attachment gone; if it cannot be reached, what it has expires.
    pub async fn cancel_upload(&self, peer: PublicKey, id: [u8; 16]) -> Result<(), String> {
        let vgen = self.vault_gen();
        // For good, running or not: what is on its way stops, and keeps nothing of it again.
        self.uploads.mark_cancelled(id);
        self.remove_attachment_caches(&peer, &id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        let (delete_job, failed_outbox) = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let pending = inner
                .vault
                .upload(&peer, &id)
                .await
                .map_err(|e| describe(&e))?;
            // One that waited for a sign-in never went: its message fails only if that outbox entry
            // still awaits an upload (a stale unstarted record left behind after `start_waiting`
            // promoted the message must only be forgotten, without failing the active message).
            if let Some(waiting) = pending.as_ref().filter(|pending| !pending.started()) {
                let still_awaits = inner.contact(&peer).is_some_and(|contact| {
                    contact
                        .state
                        .outbox
                        .iter()
                        .any(|o| o.history_index == waiting.history_index && o.awaits_upload)
                });
                if still_awaits {
                    self.fail_waiting(inner, &peer, waiting.history_index)
                        .await?;
                } else {
                    self.release(&peer, waiting.history_index);
                }
                inner
                    .vault
                    .forget_upload(&peer, &id)
                    .await
                    .map_err(|e| describe(&e))?;
                drop(guard);
                if still_awaits && let Err(e) = self.flush(&peer).await {
                    self.ui.link.set(Link::Offline(e));
                }
                return Ok(());
            }
            let Some(pending) = pending else {
                return Ok(());
            };
            let upload = upload_of(&pending)?;
            let mut announced_index = pending.is_announced().then_some(pending.history_index);
            if announced_index.is_none()
                && let Ok(Some((idx, entry))) = inner.find_attachment_entry(&peer, None, &id).await
                && entry.outgoing
            {
                announced_index = Some(idx);
            }
            let mut failed_outbox = false;
            if let Some(idx) = announced_index {
                let in_outbox = inner.contact(&peer).is_some_and(|contact| {
                    contact
                        .state
                        .outbox
                        .iter()
                        .any(|outgoing| outgoing.history_index == idx)
                });
                if in_outbox {
                    self.fail_waiting(inner, &peer, idx).await?;
                    failed_outbox = true;
                }
            }
            inner
                .vault
                .forget_upload(&peer, &id)
                .await
                .map_err(|e| describe(&e))?;
            let job = ServerDeleteJob {
                server: inner.server.clone(),
                id,
                history_index: announced_index,
                name: pending.name.clone(),
                kind: ServerDeleteKind::CancelUpload(upload),
            };
            (job, failed_outbox)
        };
        // Perform the HTTP cancel outside `self.inner.lock()` so slow deletes never block the UI.
        self.finish_server_deletes(&peer, vec![delete_job]).await;
        if failed_outbox && self.is_live(vgen) {
            if let Err(e) = self.flush(&peer).await
                && self.is_live(vgen)
            {
                self.ui.link.set(Link::Offline(e));
            }
            self.wake();
        }
        Ok(())
    }

    /// Cancel the message at `index`, to `peer`, held until this browser signs in to the server:
    /// it fails, and what waited for it goes, unless it too needs the sign-in. One whose
    /// attachment's upload has not started goes with its upload.
    pub async fn cancel_held(&self, peer: PublicKey, index: u64) -> Result<(), String> {
        let vgen = self.vault_gen();
        let waiting = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_ref().ok_or("locked")?;
            let still_awaits = inner.contacts.iter().any(|c| {
                c.peer == peer
                    && c.state
                        .outbox
                        .iter()
                        .any(|o| o.history_index == index && o.awaits_upload)
            });
            let uploads = inner
                .vault
                .uploads(Some(&peer))
                .await
                .map_err(|e| describe(&e))?;
            let found = uploads.into_iter().find_map(|(_, pending)| {
                (!pending.started() && pending.history_index == index)
                    .then(|| <[u8; 16]>::try_from(pending.id.as_slice()).ok())
                    .flatten()
            });
            if still_awaits {
                found
            } else {
                if let Some(stale_id) = found {
                    let _ = inner.vault.forget_upload(&peer, &stale_id).await;
                }
                None
            }
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        if let Some(id) = waiting {
            return self.cancel_upload(peer, id).await;
        }
        let server_deletes = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            // Gone meanwhile, e.g. pushed as the sign-in came.
            let waits = inner.contact(&peer).is_some_and(|contact| {
                contact
                    .state
                    .outbox
                    .iter()
                    .any(|outgoing| outgoing.history_index == index)
            });
            if !waits {
                self.release(&peer, index);
                return Ok(());
            }
            self.fail_waiting(inner, &peer, index).await?;
            self.prepare_cancel_uploads_for_failed(inner, &peer, &[index])
                .await
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        if !server_deletes.is_empty() {
            self.finish_server_deletes(&peer, server_deletes).await;
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.queue.clear_peer_sign_in_wait(&peer);
        if let Err(e) = self.flush(&peer).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
        self.wake();
        Ok(())
    }

    /// Cancel local state and forget any unstarted or started uploads associated with permanently
    /// failed or cancelled history entries `failed_indices`, returning any server-side HTTP delete
    /// jobs to run AFTER releasing `self.inner.lock()`.
    pub(super) async fn prepare_cancel_uploads_for_failed(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        failed_indices: &[u64],
    ) -> Vec<ServerDeleteJob> {
        if failed_indices.is_empty() {
            return Vec::new();
        }
        struct FailedAttachment {
            index: u64,
            name: String,
            key: Option<Zeroizing<[u8; attachment::KEY_LENGTH]>>,
            gone: bool,
        }
        let mut by_id: HashMap<[u8; 16], FailedAttachment> = HashMap::new();
        for &idx in failed_indices {
            if let Ok(Some(entry)) = inner.vault.entry(peer, idx).await
                && let Some(Kind::Attachment(pointer)) =
                    entry.content.as_ref().and_then(|c| c.kind.as_ref())
                && let Ok(id) = <[u8; 16]>::try_from(pointer.id.as_slice())
            {
                let key = copy_zeroizing_array::<{ attachment::KEY_LENGTH }>(&pointer.key);
                by_id.insert(
                    id,
                    FailedAttachment {
                        index: idx,
                        name: pointer.name.clone(),
                        key,
                        gone: entry.gone,
                    },
                );
            }
        }
        let server = inner.server.clone();
        let uploads = inner.vault.uploads(Some(peer)).await.unwrap_or_default();
        let mut handled_ids = std::collections::HashSet::new();
        let mut jobs = Vec::new();
        for (_, pending) in uploads {
            let Ok(id) = <[u8; 16]>::try_from(pending.id.as_slice()) else {
                continue;
            };
            let matched_index = by_id.get(&id).map(|item| item.index).or_else(|| {
                (pending.is_announced() || !pending.started())
                    .then_some(pending.history_index)
                    .filter(|idx| failed_indices.contains(idx))
            });
            if matched_index.is_none() && !by_id.contains_key(&id) {
                continue;
            }
            self.uploads.mark_cancelled(id);
            self.remove_attachment_caches(peer, &id);
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|item| item.id != id));
            if pending.started() {
                if let Ok(upload) = upload_of(&pending) {
                    handled_ids.insert(id);
                    jobs.push(ServerDeleteJob {
                        server: server.clone(),
                        id,
                        history_index: matched_index,
                        name: pending.name.clone(),
                        kind: ServerDeleteKind::CancelUpload(upload),
                    });
                }
                // If `upload_of(&pending)` fails, leave `id` out of `handled_ids` so the `by_id`
                // pass below can still attempt `attachment::delete` via `pointer.key`.
            } else {
                handled_ids.insert(id);
            }
            let _ = inner.vault.forget_upload(peer, &id).await;
        }
        for (id, item) in by_id {
            if handled_ids.contains(&id) {
                continue;
            }
            self.uploads.mark_cancelled(id);
            self.remove_attachment_caches(peer, &id);
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|entry| entry.id != id));
            if item.gone {
                self.ui.gone.update(|gone| {
                    gone.insert((*peer, item.index));
                });
                continue;
            }
            let Some(key) = item.key else {
                continue;
            };
            // Upload already finished and its `PendingUpload` was forgotten: delete the completed
            // object via its delete token outside `self.inner.lock()`.
            jobs.push(ServerDeleteJob {
                server: server.clone(),
                id,
                history_index: Some(item.index),
                name: item.name,
                kind: ServerDeleteKind::DeleteCompleted(key),
            });
        }
        jobs
    }

    /// Execute deferred server-side attachment cancels/deletes outside `self.inner.lock()`, then
    /// mark confirmed-deleted entries `gone = true` in the vault.
    pub(super) async fn finish_server_deletes(&self, peer: &PublicKey, jobs: Vec<ServerDeleteJob>) {
        let vgen = self.vault_gen();
        for job in jobs {
            if !self.is_live(vgen) {
                return;
            }
            let client = Fetch::client(&job.server);
            let deleted_on_server = match job.kind {
                ServerDeleteKind::CancelUpload(upload) => match upload.cancel(&client).await {
                    Ok(()) => true,
                    Err(e) if e.kind() == ErrorKind::NotFound => true,
                    Err(e) => {
                        if self.is_live(vgen) {
                            self.ui.log(format!(
                                "the server keeps what it has of {} until it expires: {}",
                                job.name,
                                describe(&e)
                            ));
                        }
                        false
                    }
                },
                ServerDeleteKind::DeleteCompleted(key) => {
                    match attachment::delete(&client, &job.id, &key).await {
                        Ok(()) => true,
                        Err(e) if e.kind() == ErrorKind::NotFound => true,
                        Err(e) => {
                            if self.is_live(vgen) {
                                self.ui.log(format!(
                                    "could not delete cancelled attachment from server: {}",
                                    describe(&e)
                                ));
                            }
                            false
                        }
                    }
                }
            };
            if deleted_on_server && self.is_live(vgen) {
                let _ = self.note_gone_by_id(peer, job.history_index, &job.id).await;
            }
        }
    }

    /// Show the message at `index`, to `peer`, as held until this browser signs in.
    pub(super) fn hold(&self, peer: &PublicKey, index: u64) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        self.ui.held.update(|held| {
            held.insert((*peer, index));
        });
    }

    /// Show the message at `index`, to `peer`, as no longer held.
    pub(super) fn release(&self, peer: &PublicKey, index: u64) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        if self
            .ui
            .held
            .with_untracked(|held| held.contains(&(*peer, index)))
        {
            self.ui.held.update(|held| {
                held.remove(&(*peer, index));
            });
        }
    }

    /// Hash `file` as far as `pending` may have encrypted it, confirming `prefix_hash` and
    /// `sealed_chunk_hash` while retaining the exact verified bytes for
    /// `pending.uploaded..pending.encrypted` so resume never re-reads mutable file data.
    pub(super) async fn check(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        file: &ChunkSource,
    ) -> Result<VerifiedResume, String> {
        let mut verifier = ResumeVerifier::new(pending, file.size())?;
        self.show_upload(peer, pending, UploadState::Checking);
        for index in 0..pending.encrypted {
            let chunk = read_chunk(file, index, pending.size).await?;
            verifier.push_chunk(chunk)?;
        }
        verifier.finish()
    }

    /// Upload the chunks of `pending` from where it is: `resume` carries the verified prefix hash
    /// and any already-encrypted chunk bytes for `pending.uploaded..pending.encrypted`. While it
    /// goes, the upload shows in its chat, and if it stops, it shows paused, with why. The caller
    /// has marked it running, which this ends.
    async fn run_upload(
        &self,
        peer: PublicKey,
        mut pending: PendingUpload,
        file: ChunkSource,
        resume: VerifiedResume,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let id: [u8; 16] = pending
            .id
            .as_slice()
            .try_into()
            .map_err(|_| format!("the upload of {} is corrupt", pending.name))?;
        let running_guard = scopeguard::guard(id, |id| {
            self.uploads.stop_running(&id);
        });
        let uploaded = match upload_of_with_digests(&pending, resume.digests) {
            Ok(upload) => {
                self.upload_chunks(
                    &peer,
                    &mut pending,
                    &upload,
                    &file,
                    resume.hasher,
                    resume.verified_chunks,
                )
                .await
            }
            Err(e) => Err(e),
        };
        drop(running_guard);
        // Cancelled or torn down on `pagehide`: stop quietly without touching UI or IDB.
        if !self.is_live(vgen) || self.is_cancelled(&id) {
            return Ok(());
        }
        match uploaded {
            Ok(true) => {}
            // Deleted from the server, e.g. by the peer, who did not want it: the rest need not
            // go up.
            Ok(false) => {
                self.drop_upload(&peer, id).await?;
                if pending.is_announced() {
                    let _ = self
                        .note_gone_by_id(&peer, Some(pending.history_index), &id)
                        .await;
                }
                return Err(format!(
                    "{} is no longer on the server, so its upload stopped",
                    pending.name
                ));
            }
            Err(e) => {
                let cancelled = !self.is_live(vgen) || self.is_cancelled(&id);
                let gone = if cancelled {
                    true
                } else {
                    let guard = self.lock_inner().await;
                    !self.is_live(vgen)
                        || guard
                            .as_ref()
                            .is_some_and(|inner| !self.may_keep(inner, &peer, &id))
                };
                if gone {
                    self.remove_attachment_caches(&peer, &id);
                    if self.is_live(vgen) {
                        self.ui
                            .uploads
                            .update(|uploads| uploads.retain(|upload| upload.id != id));
                    }
                    return Ok(());
                }
                self.show_upload(&peer, &pending, UploadState::Paused(e.clone()));
                return Err(e);
            }
        }
        self.remove_attachment_caches(&peer, &id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        // Forgotten, with its upload token, which is no use now: deleting it takes its delete
        // token, which its key gives.
        let guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(());
        }
        let inner = guard.as_ref().ok_or("locked")?;
        inner
            .vault
            .forget_upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))
    }

    /// Stop the upload `id`, in the chat with `peer`, if this client uploads it, for good, as
    /// the server no longer has it, and forget it.
    async fn drop_upload(&self, peer: &PublicKey, id: [u8; 16]) -> Result<(), String> {
        let vgen = self.vault_gen();
        let guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let inner = guard.as_ref().ok_or("locked")?;
        let kept = inner
            .vault
            .upload(peer, &id)
            .await
            .map_err(|e| describe(&e))?
            .is_some();
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        if !kept && !self.uploads.is_running(&id) {
            return Ok(());
        }
        self.uploads.mark_cancelled(id);
        self.remove_attachment_caches(peer, &id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        inner
            .vault
            .forget_upload(peer, &id)
            .await
            .map_err(|e| describe(&e))
    }

    /// Delete the attachment `pointer`, of the history entry `index` of the chat with `peer`,
    /// sent or received, from the server, with its delete token, which its key gives: neither
    /// peer can download it any more, though what they downloaded stays. One this client uploads
    /// stops; one the peer uploads stops too, sparing it the rest. The entry notes it, so that
    /// it is not offered again.
    pub async fn delete_attachment(
        &self,
        peer: PublicKey,
        index: u64,
        pointer: &AttachmentPointer,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let not_there = || format!("{} is not on the server", pointer.name);
        let id: [u8; 16] = pointer.id.as_slice().try_into().map_err(|_| not_there())?;
        let key = copy_zeroizing_array::<{ attachment::KEY_LENGTH }>(&pointer.key)
            .ok_or_else(not_there)?;
        let server = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            guard.as_ref().ok_or("locked")?.server.clone()
        };
        match attachment::delete(&Fetch::client(&server), &id, &key).await {
            // Gone already, e.g. expired, or deleted by the peer, as it should be.
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => {
                // Report attachment 404/Unimplemented locally without tripping global update_required.
                return Err(describe(&e));
            }
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.drop_upload(&peer, id).await?;
        self.note_gone(&peer, index, &id).await
    }

    /// Note in the history entry `index` of the chat with `peer` that its attachment `id` is
    /// gone from the server, unless the entry is no longer that attachment's message, as the
    /// chat was deleted, and maybe started again, meanwhile.
    async fn note_gone(&self, peer: &PublicKey, index: u64, id: &[u8; 16]) -> Result<(), String> {
        self.note_gone_by_id(peer, Some(index), id).await
    }

    /// Locate the history entry for attachment `id` (checking `hint_index` first, then scanning
    /// history backwards if needed) and mark it `gone = true`, updating `ui.gone` immediately.
    pub(super) async fn note_gone_by_id(
        &self,
        peer: &PublicKey,
        hint_index: Option<u64>,
        id: &[u8; 16],
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let inner = guard.as_mut().ok_or("locked")?;
        self.note_gone_inner(inner, peer, hint_index, id).await
    }

    async fn note_gone_inner(
        &self,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        hint_index: Option<u64>,
        id: &[u8; 16],
    ) -> Result<(), String> {
        let Some((index, mut entry)) = inner
            .find_attachment_entry(peer, hint_index, id)
            .await
            .map_err(|e| describe(&e))?
        else {
            return Ok(());
        };
        if self.shutting_down.get() || crate::glue::lock_released() {
            return Err("locked".into());
        }
        self.ui.gone.update(|gone| {
            gone.insert((*peer, index));
        });
        if entry.gone {
            return Ok(());
        }
        entry.gone = true;
        inner
            .save(&records(peer, &[(index, entry)]))
            .await
            .map_err(|e| describe(&e))
    }

    /// Upload the chunks of `pending` from `uploaded` on, encrypting any already-verified resumed
    /// chunk directly from `verified_chunks` and reading newer chunks from `file` in turn, unless
    /// the upload is cancelled. Returns whether the server still has the attachment: one deleted
    /// meanwhile, e.g. by the peer, is not found.
    async fn upload_chunks(
        &self,
        peer: &PublicKey,
        pending: &mut PendingUpload,
        upload: &Upload,
        file: &ChunkSource,
        mut hasher: Sha256,
        mut verified_chunks: HashMap<u32, Zeroizing<Vec<u8>>>,
    ) -> Result<bool, String> {
        let vgen = self.vault_gen();
        let lock_gen = crate::glue::lock_generation();
        let server = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(true);
            }
            guard.as_ref().ok_or("locked")?.server.clone()
        };
        // Each chunk shows how far it got as it goes: the bytes before it, and its share of what
        // its request sent.
        let before = Rc::new(Cell::new(0));
        let progress: Progress = {
            let (ui, before, id, size) = (self.ui, before.clone(), *upload.id(), pending.size);
            Rc::new(move |sent, total| {
                if crate::glue::lock_released() || crate::glue::lock_generation() != lock_gen {
                    return;
                }
                let chunk = (size - before.get()).min(CHUNK_SIZE as u64);
                let done = before.get() + chunk * sent / total.max(1);
                ui.uploads.update(|uploads| {
                    if let Some(upload) = uploads.iter_mut().find(|upload| upload.id == id) {
                        upload.done = done;
                    }
                });
            })
        };
        let attachments = Fetch::reporting(&server, progress);
        for index in pending.uploaded..upload.chunks() {
            if !self.is_live(vgen) || self.is_cancelled(upload.id()) {
                return Ok(true);
            }
            before.set((u64::from(index) * CHUNK_SIZE as u64).min(pending.size));
            self.show_upload(peer, pending, UploadState::Running);
            // Never re-read an already-verified resumed chunk (`pending.uploaded..pending.encrypted`)
            // from the live `File` handle, eliminating the AES-GCM nonce-reuse TOCTOU window.
            let plaintext = if let Some(verified) = verified_chunks.remove(&index) {
                verified
            } else {
                let raw = Zeroizing::new(read_chunk(file, index, pending.size).await?);
                let expected_len = expected_chunk_len(pending.size, index, upload.chunks())
                    .ok_or_else(|| format!("the upload of {} is corrupt", pending.name))?;
                if raw.len() != expected_len {
                    return Err(format!("that is not {}, or it changed", pending.name));
                }
                raw
            };
            if !self.is_live(vgen) {
                return Ok(true);
            }
            // Kept before the chunk is encrypted: from then on, the file must not change there.
            if index >= pending.encrypted {
                hasher.update(plaintext.as_slice());
                pending.encrypted = index + 1;
                pending.prefix_hash = hasher.clone().finalize().to_vec();
                pending.sealed_chunk_hash = Sha256::digest(plaintext.as_slice()).to_vec();
            }
            pending.uploaded = index;
            self.save_upload(peer, pending).await?;
            let chunk = upload
                .try_encrypt(index, plaintext.as_slice())
                .map_err(|e| describe(&e))?;
            if !self
                .put_chunk(peer, pending, &attachments, upload, index, &chunk)
                .await?
            {
                return Ok(false);
            }
            if !self.is_live(vgen) {
                return Ok(true);
            }
            self.keep_chunk(peer, upload.id(), index, &chunk).await?;
            pending.uploaded = index + 1;
        }
        Ok(true)
    }

    /// Upload chunk `index` of `upload`, trying again while the server cannot be reached, unless
    /// the upload is cancelled meanwhile. Returns whether the server still has the attachment.
    async fn put_chunk(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        attachments: &Connect,
        upload: &Upload,
        index: u32,
        chunk: &[u8],
    ) -> Result<bool, String> {
        let vgen = self.vault_gen();
        let mut wait = RETRY_MIN;
        loop {
            if !self.is_live(vgen) || self.is_cancelled(upload.id()) {
                return Ok(true);
            }
            match upload.put(attachments, index, chunk).await {
                Ok(()) => return Ok(true),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
                Err(e) if e.kind() == ErrorKind::Server => {
                    if !self.is_live(vgen) || self.is_cancelled(upload.id()) {
                        return Ok(true);
                    }
                    self.show_upload(peer, pending, UploadState::Retrying);
                    sleep(wait).await;
                    wait = (wait * 2).min(RETRY_MAX);
                    if !self.is_live(vgen) || self.is_cancelled(upload.id()) {
                        return Ok(true);
                    }
                }
                Err(e) => return Err(describe(&e)),
            }
        }
    }

    /// Keep `pending`, of the chat with `peer`, in the vault, unless it was cancelled or its chat
    /// deleted meanwhile, which forgot it: it must not come back.
    async fn save_upload(&self, peer: &PublicKey, pending: &PendingUpload) -> Result<(), String> {
        let guard = self.lock_inner().await;
        let inner = guard.as_ref().ok_or("locked")?;
        if !self.may_keep(inner, peer, &pending.id) {
            return Err(format!("the upload of {} was cancelled", pending.name));
        }
        inner
            .vault
            .save_upload(peer, pending)
            .await
            .map_err(|e| describe(&e))
    }

    /// Whether the vault may keep what goes with the attachment `id`, in the chat with `peer`:
    /// its upload was not cancelled, and the chat is still there. Asked under the lock, which
    /// cancelling and deleting take to forget them, so that nothing is kept after.
    pub(super) fn may_keep(&self, inner: &Inner<V>, peer: &PublicKey, id: &[u8]) -> bool {
        let cancelled = <[u8; 16]>::try_from(id).is_ok_and(|id| self.is_cancelled(&id));
        !cancelled && inner.contacts.iter().any(|contact| contact.peer == *peer)
    }

    /// Show the upload `pending`, to `peer`, as in `state`.
    pub(super) fn show_upload(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        state: UploadState,
    ) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        let Ok(id) = <[u8; 16]>::try_from(pending.id.as_slice()) else {
            return;
        };
        if self.is_cancelled(&id) {
            return;
        }
        let view = UploadView {
            peer: *peer,
            id,
            name: pending.name.clone(),
            done: (u64::from(pending.uploaded) * CHUNK_SIZE as u64).min(pending.size),
            size: pending.size,
            state,
        };
        self.ui.uploads.update(|uploads| {
            match uploads.iter_mut().find(|upload| upload.id == view.id) {
                Some(upload) => *upload = view,
                None => uploads.push(view),
            }
        });
    }

    /// Open the attachment `pointer`, in the chat with `peer`, in the viewer, from the chunks
    /// kept here, or else from the server, keeping them from then on. The viewer shows how far
    /// it got meanwhile, and closing it stops it. Once one of the peer's, sent in its message
    /// at `clock`, is downloaded whole, the peer is told.
    pub async fn open_attachment(
        &self,
        token: u64,
        peer: PublicKey,
        index: u64,
        pointer: AttachmentPointer,
        clock: u64,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Ok(());
        }
        // A message of this client's whose upload waits for it to sign in.
        if pointer.id.is_empty() {
            return Err(format!(
                "{} goes once you sign in to the server.",
                pointer.name
            ));
        }
        let Ok(id) = <[u8; 16]>::try_from(pointer.id.as_slice()) else {
            return Err("the attachment is malformed".to_string());
        };
        self.ui.opening.set(Some(Opening {
            token,
            peer,
            id,
            name: pointer.name.clone(),
            size: pointer.size,
            done: 0,
            waiting: false,
        }));
        let fetched = self
            .fetch_attachment(peer, index, &id, pointer, Waiter::Viewer(token))
            .await;
        if !self.is_live(vgen) {
            return Ok(());
        }
        if let Err(FetchError::NotFound(_)) = &fetched {
            let _ = self.note_gone_by_id(&peer, Some(index), &id).await;
        }
        let opened = self
            .told_downloaded(peer, clock, fetched.map_err(FetchError::into_message))
            .await;
        // Unless the viewer closed, navigated away, tore down on `pagehide`, or started another
        // request (even for the same attachment ID) meanwhile.
        if !self.is_live(vgen) || !self.opening(token, &id) {
            return Ok(());
        }
        match opened {
            Ok(Some(attachment)) => {
                self.ui.viewer.set(Some(attachment));
                self.ui.opening.set(None);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => {
                self.ui.opening.set(None);
                Err(e)
            }
        }
    }

    /// The attachment `pointer`, in the chat with `peer`, for the chat to show in place, as small
    /// media, as long as `shows` says it does: from the chunks kept here, or else from the
    /// server, as [`open_attachment`](Self::open_attachment) has it, and the peer is told alike;
    /// none if it stopped showing first.
    pub async fn media(
        &self,
        peer: PublicKey,
        index: u64,
        pointer: AttachmentPointer,
        clock: u64,
        shows: &dyn Fn() -> bool,
    ) -> Result<Option<Attachment>, String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Ok(None);
        }
        let Ok(id) = <[u8; 16]>::try_from(pointer.id.as_slice()) else {
            return Err("the attachment is malformed".to_string());
        };
        let fetched = self
            .fetch_attachment(peer, index, &id, pointer, Waiter::Chat(shows))
            .await;
        if !self.is_live(vgen) {
            return Ok(None);
        }
        if let Err(FetchError::NotFound(_)) = &fetched {
            let _ = self.note_gone_by_id(&peer, Some(index), &id).await;
        }
        self.told_downloaded(peer, clock, fetched.map_err(FetchError::into_message))
            .await
    }

    /// The attachment `fetched`, once the peer is told it is downloaded, if it is the peer's,
    /// sent in its message at `clock`, and came from the server now.
    async fn told_downloaded(
        &self,
        peer: PublicKey,
        clock: u64,
        fetched: Result<Option<(Attachment, bool)>, String>,
    ) -> Result<Option<Attachment>, String> {
        let vgen = self.vault_gen();
        let Some((attachment, from_server)) = fetched? else {
            return Ok(None);
        };
        if !self.is_live(vgen) {
            return Ok(None);
        }
        if from_server
            && clock > 0
            && let Err(e) = self.downloaded(peer, clock).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
        Ok(Some(attachment))
    }

    /// Tell `peer` that its attachment, sent in its message at `clock`, is downloaded.
    pub(super) async fn downloaded(&self, peer: PublicKey, clock: u64) -> Result<(), String> {
        let vgen = self.vault_gen();
        {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            if contact.tell_downloaded(clock) {
                inner.save_state().await.map_err(|e| describe(&e))?;
            }
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.flush(&peer).await.map(drop)
    }

    /// Whether the viewer still waits for the attachment `id` of preview request `token`.
    fn opening(&self, token: u64, id: &[u8; 16]) -> bool {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return false;
        }
        self.ui.opening.with_untracked(|opening| {
            opening
                .as_ref()
                .is_some_and(|opening| opening.token == token && opening.id == *id)
        })
    }

    /// Note how far opening the attachment `id` of preview request `token` got.
    pub(super) fn opened(&self, token: u64, id: &[u8; 16], done: u64, waiting: bool) {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return;
        }
        self.ui.opening.update(|opening| {
            if let Some(opening) = opening
                .as_mut()
                .filter(|opening| opening.token == token && opening.id == *id)
            {
                (opening.done, opening.waiting) = (done, waiting);
            }
        });
    }

    /// Whether `waiter` still waits for the attachment `id`.
    pub(super) fn waits(&self, waiter: Waiter<'_>, id: &[u8; 16]) -> bool {
        if self.shutting_down.get() || crate::glue::lock_released() {
            return false;
        }
        match waiter {
            Waiter::Viewer(token) => self.opening(token, id),
            Waiter::Chat(shows) => shows(),
        }
    }

    /// The file of the attachment `pointer`, whose ID is `id`, in the chat with `peer`, and
    /// whether any of it came from the server, as it was not all downloaded before; none if
    /// `waiter` stopped waiting for it. The viewer shows how far it got.
    async fn fetch_attachment(
        &self,
        peer: PublicKey,
        index: u64,
        id: &[u8; 16],
        mut pointer: AttachmentPointer,
        waiter: Waiter<'_>,
    ) -> Result<Option<(Attachment, bool)>, FetchError> {
        // The sender's own, while on the page that chose it: keyed by `(peer, id, key_hash)` so
        // another peer or mismatched key can never read a cached plaintext file (M-13).
        let key_hash = attachment_key_hash(&pointer.key);
        let file = self.uploads.get_file(&(peer, *id, key_hash));
        if let Some(file) = file {
            let data = file.read_all().await.map_err(FetchError::Other)?;
            let attachment = Attachment {
                name: std::mem::take(&mut pointer.name),
                mime: std::mem::take(&mut pointer.mime),
                data: Arc::new(data),
            };
            return Ok(Some((attachment, false)));
        }
        let fetching = self
            .fetching(peer, index, &pointer)
            .await
            .map_err(FetchError::Other)?;
        // It grows as its chunks decrypt, not to the size the peer claims, which nothing backs
        // until they do.
        let (mut data, mut fetched) = (vec![], false);
        for chunk_index in 0..fetching.chunks {
            let Some((plaintext, from_server)) = self.chunk(&fetching, chunk_index, waiter).await?
            else {
                return Ok(None);
            };
            fetched |= from_server;
            data.extend(plaintext);
            if let Waiter::Viewer(token) = waiter {
                self.opened(token, id, data.len() as u64, false);
            }
        }
        if data.len() as u64 != pointer.size {
            return Err(FetchError::Other(format!(
                "{} is not the size it should be",
                pointer.name
            )));
        }
        let attachment = Attachment {
            name: std::mem::take(&mut pointer.name),
            mime: std::mem::take(&mut pointer.mime),
            data: Arc::new(data),
        };
        Ok(Some((attachment, fetched)))
    }

    /// What fetching the attachment `pointer`, in the chat with `peer`, takes.
    pub(super) async fn fetching(
        &self,
        peer: PublicKey,
        index: u64,
        pointer: &AttachmentPointer,
    ) -> Result<Fetching, String> {
        let malformed = || "the attachment is malformed".to_string();
        let id = <[u8; 16]>::try_from(pointer.id.as_slice()).map_err(|_| malformed())?;
        let key = copy_zeroizing_array::<{ attachment::KEY_LENGTH }>(&pointer.key)
            .ok_or_else(malformed)?;
        let key_hash = attachment_key_hash(key.as_slice());
        if pointer.size > MAX_FILE_SIZE as u64 {
            return Err(format!(
                "{} is {}; files go up to {}.",
                pointer.name,
                size_u64(pointer.size),
                size_u64(MAX_FILE_SIZE as u64)
            ));
        }
        let chunks =
            u32::try_from(attachment::chunk_count(pointer.size)).map_err(|_| malformed())?;
        let guard = self.lock_inner().await;
        let inner = guard.as_ref().ok_or("locked")?;
        let unfinished = inner
            .vault
            .upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))?
            .map(|pending| pending.uploaded);
        Ok(Fetching {
            peer,
            index,
            id,
            key,
            key_hash,
            name: pointer.name.clone(),
            size: pointer.size,
            chunks,
            unfinished,
            attachments: Fetch::client(&inner.server),
        })
    }

    /// Chunk `index` of the attachment `fetching` fetches, decrypted: kept here, or else fetched
    /// from the server, waiting for it while it is uploaded, and kept from then on; and whether
    /// it came from the server. None if `waiter` stopped waiting for it.
    pub(super) async fn chunk(
        &self,
        fetching: &Fetching,
        index: u32,
        waiter: Waiter<'_>,
    ) -> Result<Option<(Vec<u8>, bool)>, FetchError> {
        if !self.waits(waiter, &fetching.id) {
            return Ok(None);
        }
        let last = index + 1 == fetching.chunks;
        let expected_len =
            expected_chunk_len(fetching.size, index, fetching.chunks).ok_or_else(|| {
                FetchError::Other(format!("{} is not the size it should be", fetching.name))
            })?;
        let decrypt_and_validate = |ciphertext: &[u8]| -> Result<Vec<u8>, FetchError> {
            let plaintext =
                attachment::decrypt_chunk(&fetching.key, &fetching.id, index, last, ciphertext)
                    .map_err(|_| {
                        FetchError::Other(format!("{} does not decrypt", fetching.name))
                    })?;
            if plaintext.len() != expected_len {
                return Err(FetchError::Other(format!(
                    "{} is not the size it should be",
                    fetching.name
                )));
            }
            Ok(plaintext)
        };
        if let Some(cached) = self
            .kept_chunk(&fetching.peer, &fetching.id, index)
            .await
            .map_err(FetchError::Other)?
            && let Ok(plaintext) = decrypt_and_validate(&cached)
        {
            return Ok(Some((plaintext, false)));
        }
        // Missing locally, or a cached chunk failed decryption / expected length validation:
        // re-fetch from the server below and repair IndexedDB via `keep_chunk`.
        if fetching
            .unfinished
            .is_some_and(|uploaded| index >= uploaded)
        {
            return Err(FetchError::Other(format!(
                "{} is not all uploaded: choose the file again to go on",
                fetching.name
            )));
        }
        let Some(chunk) = self
            .await_chunk(
                &fetching.attachments,
                &fetching.name,
                &fetching.id,
                index,
                waiter,
            )
            .await?
        else {
            return Ok(None);
        };
        let plaintext = decrypt_and_validate(&chunk)?;
        // Kept only once it decrypts AND matches `expected_len`, repairing any corrupt cached
        // chunk while preventing spoofed `pointer.size` from polluting IndexedDB.
        self.keep_chunk(&fetching.peer, &fetching.id, index, &chunk)
            .await
            .map_err(FetchError::Other)?;
        Ok(Some((plaintext, true)))
    }

    /// Chunk `index` of the attachment `id`, named `name`, from the server, waiting for it while
    /// it is uploaded, unless no chunk comes for [`STALLED`] milliseconds; none if `waiter`
    /// stopped waiting for it meanwhile.
    async fn await_chunk(
        &self,
        attachments: &Connect,
        name: &str,
        id: &[u8; 16],
        index: u32,
        waiter: Waiter<'_>,
    ) -> Result<Option<Vec<u8>>, FetchError> {
        let (mut waited, mut wait) = (0, POLL_CHUNK_MIN);
        loop {
            if !self.waits(waiter, id) {
                return Ok(None);
            }
            match attachment::download_chunk(attachments, id, index).await {
                Ok(Some(chunk)) => return Ok(Some(chunk)),
                Ok(None) if waited < STALLED => {
                    if let Waiter::Viewer(token) = waiter {
                        self.ui.opening.update(|opening| {
                            if let Some(opening) = opening
                                .as_mut()
                                .filter(|opening| opening.token == token && opening.id == *id)
                            {
                                opening.waiting = true;
                            }
                        });
                    }
                    sleep(wait).await;
                    waited += wait;
                    wait = (wait * 2).min(POLL_CHUNK_MAX);
                }
                Ok(None) => {
                    return Err(FetchError::Other(format!(
                        "{name} is still being uploaded, but nothing came for a while; open it \
                         again later"
                    )));
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    return Err(FetchError::NotFound(format!(
                        "{name} is no longer on the server: it was deleted from the server, its \
                         upload was cancelled, or it expired (the server keeps attachments \
                         temporarily)"
                    )));
                }
                Err(e) => return Err(FetchError::Other(describe(&e))),
            }
        }
    }

    /// Keep chunk `index` of the attachment `id`, in the chat with `peer`, unless its upload was
    /// cancelled or the chat deleted meanwhile.
    async fn keep_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
    ) -> Result<(), String> {
        let guard = self.lock_inner().await;
        let inner = guard.as_ref().ok_or("locked")?;
        if !self.may_keep(inner, peer, id) {
            return Ok(());
        }
        inner
            .vault
            .put_chunk(peer, id, index, chunk)
            .await
            .map_err(|e| describe(&e))
    }

    /// Chunk `index` of the attachment `id`, in the chat with `peer`, if kept.
    async fn kept_chunk(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
    ) -> Result<Option<Vec<u8>>, String> {
        let guard = self.lock_inner().await;
        let inner = guard.as_ref().ok_or("locked")?;
        inner
            .vault
            .chunk(peer, id, index)
            .await
            .map_err(|e| describe(&e))
    }

    /// The files of the chat with `peer`, newest first, as its file browser lists them: those its
    /// messages carry, and its attachments. The whole history is read, a page at a time, without
    /// the files' bytes, each page under the lock of its own, so that syncing and sending go on
    /// meanwhile.
    pub async fn files(&self, peer: PublicKey) -> Result<Vec<FileView>, String> {
        let vgen = self.vault_gen();
        let mut files = vec![];
        // The server's time, by which the attachments it deleted already are not offered.
        let now = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            guard.as_ref().ok_or("locked")?.client.clock().now()
        };
        let mut end = u64::MAX;
        loop {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_ref().ok_or("locked")?;
            let contact = inner
                .contacts
                .iter()
                .find(|contact| contact.peer == peer)
                .ok_or("no such chat")?;
            // Not past its end, as the chat may have been deleted and started again meanwhile.
            end = end.min(contact.state.history_len);
            if end == 0 {
                break;
            }
            let page = inner
                .vault
                .history(&peer, end, HISTORY_SHOWN)
                .await
                .map_err(|e| describe(&e))?;
            for (index, entry) in page.into_iter().rev() {
                // Sorted by content as it came, if it came with its bytes; else by its name and
                // type, as an attachment.
                let sort = entry.sort();
                let gone = entry.gone;
                let message = contact.message(index, entry);
                let (name, mime, size) = match &message.body {
                    Body::File(file) => (file.name.clone(), file.mime.clone(), file.size),
                    Body::Remote(remote) => (
                        remote.pointer.name.clone(),
                        remote.pointer.mime.clone(),
                        remote.pointer.size,
                    ),
                    _ => continue,
                };
                let (deletable, gone) = match &message.body {
                    Body::Remote(remote) => {
                        let gone = gone || expired(&remote.pointer, now);
                        (!gone && uploaded(&remote.pointer), gone)
                    }
                    _ => (false, false),
                };
                files.push(FileView {
                    index,
                    at: message.at,
                    outgoing: message.outgoing,
                    deletable,
                    gone,
                    failed: message.delivery == Delivery::Failed,
                    sort: match sort {
                        Sort::Unknown => preview::sort(&name, &mime, &[]),
                        sort => sort,
                    },
                    name,
                    size,
                    body: message.body,
                });
            }
            end = end.saturating_sub(HISTORY_SHOWN);
        }
        Ok(files)
    }
}

/// Chunk `index` of `file`, of `size` bytes, as the attachment cuts it.
pub(super) async fn read_chunk(
    file: &ChunkSource,
    index: u32,
    size: u64,
) -> Result<Vec<u8>, String> {
    let start = u64::from(index) * CHUNK_SIZE as u64;
    let end = (start + CHUNK_SIZE as u64).min(size);
    match file {
        ChunkSource::File(file) => read(file, start, end).await,
        #[cfg(all(test, not(target_arch = "wasm32")))]
        ChunkSource::Bytes { name, data, .. } => {
            let start = usize::try_from(start)
                .map_err(|_| format!("cannot read {name}: offset overflow"))?;
            let end =
                usize::try_from(end).map_err(|_| format!("cannot read {name}: offset overflow"))?;
            data.get(start..end)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| format!("cannot read {name}: slice out of bounds"))
        }
    }
}

/// Whether the attachment `pointer` went up, rather than waits for a sign-in, so that either
/// peer can delete it from the server while it is there.
fn uploaded(pointer: &AttachmentPointer) -> bool {
    pointer.id.len() == 16 && pointer.key.len() == 32
}

/// Whether the attachment `pointer` expired by `now`, the server's time, as far as its message
/// tells.
fn expired(pointer: &AttachmentPointer, now: u64) -> bool {
    pointer.expires != 0 && pointer.expires <= now
}

/// The upload of `pending`, to go on with, refusing re-encryption below `pending.encrypted`
/// unless matched by a verified chunk digest.
pub(super) fn upload_of(pending: &PendingUpload) -> Result<Upload, String> {
    upload_of_with_digests(pending, HashMap::new())
}

/// The upload of `pending` bound to verified per-chunk SHA-256 `digests` for resumed chunks
/// `pending.uploaded..pending.encrypted`.
pub(super) fn upload_of_with_digests(
    pending: &PendingUpload,
    digests: HashMap<u32, [u8; 32]>,
) -> Result<Upload, String> {
    let corrupt = || format!("the upload of {} is corrupt", pending.name);
    let chunks = u32::try_from(attachment::chunk_count(pending.size)).map_err(|_| corrupt())?;
    let id: [u8; 16] = pending.id.as_slice().try_into().map_err(|_| corrupt())?;
    let token = copy_zeroizing_array::<16>(&pending.token).ok_or_else(corrupt)?;
    let key =
        copy_zeroizing_array::<{ attachment::KEY_LENGTH }>(&pending.key).ok_or_else(corrupt)?;
    let sealed_chunks = pending.encrypted.max(pending.uploaded);
    Ok(Upload::resume_with_digests(
        id,
        token,
        key,
        chunks,
        sealed_chunks,
        digests,
    ))
}

/// The bytes of `file` from `start` to `end`.
async fn read(file: &web_sys::File, start: u64, end: u64) -> Result<Vec<u8>, String> {
    let failed = |e| format!("cannot read {}: {}", file.name(), js_error(e));
    let part = file
        .slice_with_f64_and_f64(start as f64, end as f64)
        .map_err(failed)?;
    let buffer = JsFuture::from(part.array_buffer()).await.map_err(failed)?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}
