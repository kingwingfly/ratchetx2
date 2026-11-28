//! Attachment uploads, downloads and local file storage.

use super::{
    Engine, HISTORY_SHOWN, Inner, MAX_FILE_SIZE, NOT_SIGNED_IN_HERE, POLL_CHUNK_MAX,
    POLL_CHUNK_MIN, RETRY_MAX, RETRY_MIN, STALLED, VaultStore, WAITS_SIGN_IN, attachment_key_hash,
    origin, records, same_server,
};
use crate::content::{AttachmentPointer, Content, Kind};
use crate::preview;
use crate::preview::Sort;
use crate::state::{
    Attachment, Body, Delivery, FileView, Link, Opening, Step, UploadState, UploadView,
};
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
    pub(super) id: [u8; 16],
    history_index: Option<u64>,
    name: String,
    pub(super) kind: ServerDeleteKind,
}

pub(super) enum ServerDeleteKind {
    CancelUpload(Upload),
    DeleteCompleted(Zeroizing<[u8; attachment::KEY_LENGTH]>),
}

impl ServerDeleteJob {
    pub(super) fn for_cancelled_pending(
        server: String,
        pending: &PendingUpload,
    ) -> Result<Self, String> {
        let id: [u8; 16] = pending
            .id
            .as_slice()
            .try_into()
            .map_err(|_| "corrupt upload id".to_string())?;
        let upload = upload_of(pending)?;
        Ok(Self {
            server,
            id,
            history_index: Some(pending.history_index),
            name: pending.name.clone(),
            kind: ServerDeleteKind::CancelUpload(upload),
        })
    }

    pub(super) fn for_completed(
        server: String,
        id: [u8; 16],
        history_index: Option<u64>,
        name: String,
        key: Zeroizing<[u8; attachment::KEY_LENGTH]>,
    ) -> Self {
        Self {
            server,
            id,
            history_index,
            name,
            kind: ServerDeleteKind::DeleteCompleted(key),
        }
    }
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
pub(super) fn copy_zeroizing_array<const N: usize>(bytes: &[u8]) -> Option<Zeroizing<[u8; N]>> {
    if bytes.len() != N {
        return None;
    }
    let mut out = Zeroizing::new([0u8; N]);
    out.copy_from_slice(bytes);
    Some(out)
}

/// Error fetching an attachment chunk, preserving HTTP 404 (`NotFound`) and the pinned
/// conversation generation so callers only mark the attachment gone in the same conversation.
#[derive(Debug)]
pub(super) enum FetchError {
    NotFound {
        message: String,
        conversation_gen: Option<u64>,
    },
    Other(String),
}

/// Error announcing a newly started attachment in chat history, distinguishing pre-send failure
/// (safe to cancel on the server) from post-send vault save failure (where the peer may already
/// hold the attachment pointer).
pub(super) enum AnnounceError {
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
            Self::NotFound { message, .. } | Self::Other(message) => message,
        }
    }
}

/// What fetching an attachment's chunks takes, see [`Engine::chunk`].
pub(super) struct Fetching {
    /// The chat it is in.
    pub(super) peer: PublicKey,
    /// Conversation generation captured when starting the fetch (`R8-P2-5`).
    pub(super) conversation_gen: u64,
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
    /// Whether this attachment is already known deleted/missing on the server (`R22-P3-3`):
    /// locally cached chunks still open offline, while cache misses fail immediately without
    /// issuing `GetChunk`.
    pub(super) known_gone: bool,
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
        let (server, conv_gen) = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_ref().ok_or("locked")?;
            let contact = inner
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .ok_or("no such chat")?;
            if contact.state.request {
                return Err("accept the request first".into());
            }
            if contact.state.provisional {
                return Err("chat is still starting; please wait.".into());
            }
            if contact.state.quarantined {
                return Err("approve classical encryption or upgrade to post-quantum first".into());
            }
            (inner.server.clone(), contact.state.conversation_gen)
        };
        let signs_in_here = same_server(&server, &origin());
        let started =
            session::start_upload_with(&Fetch::client_without_refused_hook(&server), size).await;
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
                self.wait_for_sign_in(peer, conv_gen, file).await?;
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
        if let Err(e) = self
            .save_upload_for_gen(&peer, &pending, Some(conv_gen))
            .await
        {
            // R9-P1-1: If vault teardown / `pagehide` fired during the IDB commit, the write may
            // already have committed before `ensure_lock_owned()` failed; preserve the server
            // allocation so unlock can resume cleanly instead of stranding a 404 orphan.
            if self.is_live(vgen) {
                let _ = upload.cancel(&Fetch::client(&server)).await;
            }
            return Err(e);
        }
        if !self.is_live(vgen) {
            // R8-P1-4: `save_upload_for_gen` already persisted `PendingUpload` durably; preserve
            // the server allocation across lock/`pagehide` teardown so unlock can resume cleanly.
            return Err("locked".into());
        }
        self.uploads.insert_file(
            (peer, *upload.id(), attachment_key_hash(upload.key())),
            file.clone(),
        );
        let pending = match self.announce_for_gen(&peer, pending, Some(conv_gen)).await {
            Ok(Some(pending)) => pending,
            Ok(None) => {
                if !self.is_live(vgen) {
                    return Err("locked".into());
                }
                self.uploads.mark_cancelled(*upload.id());
                self.remove_attachment_caches(&peer, upload.id());
                let _ = upload.cancel(&Fetch::client(&server)).await;
                return Ok(());
            }
            Err(AnnounceError::NotSent(e)) => {
                // R9-P1-1: `PendingUpload` (and possibly the `HistoryEntry` + `Outbox` item) was
                // already saved durably before `announce_for_gen`; NEVER send `DeleteAttachment`
                // on vault lock / `pagehide` teardown or if forgetting the vault record failed.
                if !self.is_live(vgen) {
                    return Err(e);
                }
                self.uploads.mark_cancelled(*upload.id());
                self.remove_attachment_caches(&peer, upload.id());
                let forgot = {
                    let guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        false
                    } else if let Some(inner) = guard.as_ref() {
                        inner.vault.forget_upload(&peer, upload.id()).await.is_ok()
                            && self.is_live(vgen)
                    } else {
                        false
                    }
                };
                if forgot {
                    let _ = upload.cancel(&Fetch::client(&server)).await;
                }
                return Err(e);
            }
            Err(AnnounceError::SaveAfterSend { error, pending }) => {
                // R8-P1-4: Once the pointer may already have reached the peer, NEVER send
                // `DeleteAttachment` solely because the tab locked or closed (`!is_live(vgen)`).
                // Only cancel on the server when the vault is still live and explicitly discarded
                // the upload (cancelled or deleted/recreated conversation).
                if !self.is_live(vgen) {
                    return Err(error);
                }
                enum PostSendAction {
                    Locked,
                    Keep,
                    Cancel,
                }
                let action = {
                    let guard = self.lock_inner().await;
                    if !self.is_live(vgen) {
                        PostSendAction::Locked
                    } else if let Some(inner) = guard.as_ref() {
                        if self.may_keep_for_gen(inner, &peer, upload.id(), Some(conv_gen)) {
                            PostSendAction::Keep
                        } else {
                            PostSendAction::Cancel
                        }
                    } else {
                        PostSendAction::Locked
                    }
                };
                match action {
                    PostSendAction::Locked => {}
                    PostSendAction::Keep => {
                        self.show_upload(&peer, &pending, UploadState::Paused(error.clone()));
                    }
                    PostSendAction::Cancel => {
                        self.uploads.mark_cancelled(*upload.id());
                        self.remove_attachment_caches(&peer, upload.id());
                        let _ = upload.cancel(&Fetch::client(&server)).await;
                    }
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
        expected_conv_gen: u64,
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
        if contact.state.conversation_gen != expected_conv_gen {
            return Err("chat changed; please retry.".into());
        }
        if contact.state.request {
            return Err("accept the request first".into());
        }
        if contact.state.provisional {
            return Err("chat is still starting; please wait.".into());
        }
        if contact.state.quarantined {
            return Err("approve classical encryption or upgrade to post-quantum first".into());
        }
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
        let pointer = AttachmentPointer {
            id: vec![],
            key: vec![],
            size: waiting.size,
            name: waiting.name.clone(),
            mime: waiting.mime.clone(),
            expires: 0,
        };
        // R17-P2-7: Persist `waiting` checkpoint + placeholder `HistoryEntry` + `OutgoingRecord` +
        // `Outgoing { awaits_upload: true, attachment_id: waiting.id }` in ONE atomic transaction
        // so a storage failure can never leave two waiting uploads claiming the same index.
        let view = inner.add_waiting_upload(&peer, pointer, &waiting).await?;
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
        for (peer, pending) in waiting.into_iter().filter(|(_, p)| !p.has_started_state()) {
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
                                !p.has_started_state()
                                    && inner.contacts.iter().any(|c| {
                                        c.peer == peer
                                            && c.state.outbox.iter().any(|o| {
                                                o.history_index == p.history_index
                                                    && o.awaits_upload
                                                    && (o.attachment_id.is_empty()
                                                        || o.attachment_id == p.id)
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
            let result = self.start_waiting_with_mode(peer, id, file, true).await;
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
        self.start_waiting_with_mode(peer, waiting, file, false)
            .await
    }

    async fn start_waiting_with_mode(
        self: &Rc<Self>,
        peer: PublicKey,
        waiting: [u8; 16],
        file: ChunkSource,
        background: bool,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let (kept, server, conv_gen) = {
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
                .filter(|pending| !pending.has_started_state())
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
            // Validate the waiting message and contact BEFORE allocating a server upload so a
            // missing history entry cannot orphan a server upload or a `started = true` record.
            let entry_exists = inner
                .vault
                .entry(&peer, kept.history_index)
                .await
                .map_err(|e| describe(&e))?
                .is_some();
            if !entry_exists {
                return Err("its message is gone".into());
            }
            let Some(contact) = inner.contact(&peer) else {
                return Err("no such chat".into());
            };
            let conv_gen = contact.state.conversation_gen;
            if !self.is_live(vgen) || self.is_cancelled(&waiting) {
                return Ok(());
            }
            (kept, inner.server.clone(), conv_gen)
        };
        let started =
            session::start_upload_with(&Fetch::client_without_refused_hook(&server), kept.size)
                .await;
        let upload = match started {
            Ok(upload) => upload,
            Err(e) if e.kind() == ErrorKind::SignInRequired => {
                if !self.is_live(vgen) || self.is_cancelled(&waiting) {
                    return Ok(());
                }
                // R23-P2-1: Re-validate conversation generation and waiting outbox entry under
                // `self.inner` before re-caching `file`, showing a paused card, or opening
                // `Dialog::SignIn` so a late 403 after chat delete/recreate or cancellation never
                // leaks file handles or pops a spurious sign-in dialog.
                let still_awaited = {
                    let guard = self.lock_inner().await;
                    self.is_live(vgen)
                        && !self.is_cancelled(&waiting)
                        && guard.as_ref().is_some_and(|inner| {
                            inner.contacts.iter().any(|c| {
                                c.peer == peer
                                    && c.state.conversation_gen == conv_gen
                                    && c.state.outbox.iter().any(|outgoing| {
                                        outgoing.history_index == kept.history_index
                                            && outgoing.awaits_upload
                                            && (outgoing.attachment_id.is_empty()
                                                || outgoing.attachment_id == kept.id)
                                    })
                            })
                        })
                };
                if !still_awaited || !self.is_live(vgen) || self.is_cancelled(&waiting) {
                    return Ok(());
                }
                self.uploads
                    .insert_file((peer, waiting, attachment_key_hash(&kept.key)), file);
                self.show_upload(&peer, &kept, UploadState::Paused(WAITS_SIGN_IN.to_string()));
                if same_server(&server, &origin()) {
                    self.ask_sign_in_for(background);
                }
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
        // Cancelled or locked meanwhile: cancel on server outside `self.inner`.
        if !self.is_live(vgen) || self.is_cancelled(&waiting) {
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Ok(());
        }
        let mut guard = self.lock_inner().await;
        if !self.is_live(vgen) || self.is_cancelled(&waiting) {
            drop(guard);
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Ok(());
        }
        let Some(inner) = guard.as_mut() else {
            drop(guard);
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Err("locked".into());
        };
        let still_awaited = inner.contact(&peer).is_some_and(|contact| {
            contact.state.conversation_gen == conv_gen
                && contact.state.outbox.iter().any(|outgoing| {
                    outgoing.history_index == kept.history_index && outgoing.awaits_upload
                })
        });
        let entry_opt = if still_awaited {
            match inner.vault.entry(&peer, kept.history_index).await {
                Ok(entry) => entry,
                Err(e) => {
                    drop(guard);
                    let _ = upload.cancel(&Fetch::client(&server)).await;
                    return Err(describe(&e));
                }
            }
        } else {
            None
        };
        let Some(mut entry) = entry_opt else {
            drop(guard);
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Ok(());
        };
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
                        outgoing.attachment_id = pending.id.clone();
                    }
                }
                inner
                    .promote_upload_with(
                        &peer,
                        &waiting,
                        Some(&pending),
                        &records(&peer, &changed),
                        &[(peer, kept.history_index, Some(record))],
                    )
                    .await
                    .map_err(|e| describe(&e))
            })
            .await;
        if let Err(e) = promoted {
            drop(guard);
            // R9-P1-1: If vault teardown / `pagehide` fired while the atomic promotion transaction
            // was committing, `promote_upload_with` may have already committed before
            // `ensure_lock_owned()` returned `Err`; preserve the server allocation across teardown.
            if self.is_live(vgen) {
                let _ = upload.cancel(&Fetch::client(&server)).await;
            }
            return Err(e);
        }
        if !self.is_live(vgen) {
            return Ok(());
        }
        // Cancelled while it started, which found nothing left to cancel: it goes no further,
        // and its message reverts to an un-uploaded failed attachment without publishing the
        // cancelled pointer ID to the UI.
        if self.is_cancelled(&waiting) {
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
            // R10-P2-6: Atomically delete the newly promoted `PendingUpload`, remove the outbox
            // item, delete the `OutgoingRecord`, and mark the `HistoryEntry` `Failed` in ONE
            // IndexedDB transaction BEFORE cancelling the server upload allocation so a storage
            // failure or pagehide teardown can never delete the R2 object out from under a still-
            // persisted upload or leave an orphaned upload checkpoint without its outbox record.
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
                        .promote_upload_with(
                            &peer,
                            upload.id(),
                            None,
                            &records(&peer, &changed),
                            &[(peer, kept.history_index, None)],
                        )
                        .await
                        .map_err(|e| describe(&e))
                })
                .await;
            if self.is_live(vgen) {
                self.uploads.mark_cancelled(*upload.id());
                self.remove_attachment_caches(&peer, &waiting);
                self.remove_attachment_caches(&peer, upload.id());
                if reverted.is_ok() {
                    self.release(&peer, kept.history_index);
                    self.show_changes(inner, &peer, &changed);
                } else {
                    // R11-P2-1: Atomic rollback failed transiently. Block `Engine::flush` from
                    // announcing the cancelled pointer and complete the atomic vault rollback +
                    // server `DeleteAttachment` as soon as storage recovers.
                    self.uploads.insert_pending_cancel_rollback(
                        (peer, kept.history_index),
                        super::runtime::PendingCancelRollback {
                            conversation_gen: conv_gen,
                            pending: pending.clone(),
                            failed_entry: changed[0].1.clone(),
                        },
                    );
                }
            }
            drop(guard);
            if reverted.is_ok() && self.is_live(vgen) {
                let _ = upload.cancel(&Fetch::client(&server)).await;
            }
            reverted?;
            if self.is_live(vgen)
                && let Err(e) = self.flush_with_mode(&peer, background).await
                && self.is_live(vgen)
            {
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
        if let Err(e) = self.flush_with_mode(&peer, background).await
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
        pending: PendingUpload,
    ) -> Result<Option<PendingUpload>, AnnounceError> {
        self.announce_for_gen(peer, pending, None).await
    }

    pub(super) async fn announce_for_gen(
        &self,
        peer: &PublicKey,
        mut pending: PendingUpload,
        expected_gen: Option<u64>,
    ) -> Result<Option<PendingUpload>, AnnounceError> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Err(AnnounceError::NotSent("locked".into()));
        }
        if pending.has_announced_state() {
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
                .find_attachment_entry(peer, None, &pending.id, Some(true))
                .await
                .map_err(|e| AnnounceError::NotSent(describe(&e)))?
                .map(|(idx, _)| idx);
            if !self.is_live(vgen) {
                return Err(AnnounceError::NotSent("locked".into()));
            }
            if !self.may_keep_for_gen(inner, peer, &pending.id, expected_gen) {
                if let Some(id) = id_arr {
                    self.remove_attachment_caches(peer, &id);
                    self.ui
                        .uploads
                        .update(|uploads| uploads.retain(|item| item.id != id));
                }
                return Ok(None);
            }
            // R8-P2-1: If the conversation still exists at the same `conversation_gen` and the
            // upload was NOT cancelled, but the contact became a request or quarantined before
            // announcement, return `Err(AnnounceError::NotSent)` instead of `Ok(None)` so
            // `send_attachment` forgets the vault record + cancels server allocation + reports the
            // error, while `resume_upload_source` keeps the upload visibly paused with the reason.
            if found.is_none()
                && let Some(c) = inner.contacts.iter().find(|c| c.peer == *peer)
                && (c.state.request || c.state.quarantined)
            {
                let reason = if c.state.request {
                    "accept the request first"
                } else {
                    "approve classical encryption or upgrade to post-quantum first"
                };
                return Err(AnnounceError::NotSent(reason.into()));
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
                        .map_err(|e| {
                            if !self.is_live(vgen) {
                                AnnounceError::SaveAfterSend {
                                    error: e,
                                    pending: Box::new(pending.clone()),
                                }
                            } else {
                                AnnounceError::NotSent(e)
                            }
                        })?;
                    if !self.is_live(vgen) {
                        // R9-P1-1: `inner.add` already persisted the `HistoryEntry` and `Outbox`
                        // item durably; classify as `SaveAfterSend` so callers never delete the
                        // server upload allocation on teardown.
                        pending.history_index = view.index;
                        return Err(AnnounceError::SaveAfterSend {
                            error: "locked".into(),
                            pending: Box::new(pending),
                        });
                    }
                    let index = view.index;
                    // R13-P2-1: Mark `PendingUpload` announced with its exact `history_index`
                    // BEFORE releasing `self.inner` to invoke `self.flush(peer)` so a reload or
                    // `pagehide` during flush never strands it in `UPLOAD_STATE_STARTED` (`history_index == 0`).
                    pending.announced = true;
                    pending.upload_state = UPLOAD_STATE_ANNOUNCED;
                    pending.history_index = index;
                    if let Err(e) = inner.vault.save_upload(peer, &pending).await {
                        if self.is_live(vgen) {
                            self.show_new(inner, peer, vec![view]);
                            self.refresh_contacts(inner);
                        }
                        return Err(AnnounceError::SaveAfterSend {
                            error: describe(&e),
                            pending: Box::new(pending),
                        });
                    }
                    if !self.is_live(vgen) {
                        return Err(AnnounceError::SaveAfterSend {
                            error: "locked".into(),
                            pending: Box::new(pending),
                        });
                    }
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
        let needs_announce_save = !added_new;
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
        if !self.may_keep_for_gen(inner, peer, &pending.id, expected_gen) {
            if let Some(id) = id_arr {
                self.remove_attachment_caches(peer, &id);
                self.ui
                    .uploads
                    .update(|uploads| uploads.retain(|item| item.id != id));
            }
            return Ok(None);
        }
        if needs_announce_save && let Err(e) = inner.vault.save_upload(peer, &pending).await {
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
        if !pending.has_started_state() {
            let key = (peer, id, attachment_key_hash(&[]));
            let file = file
                .or_else(|| self.uploads.get_file(&key))
                .ok_or("choose the file again")?;
            return self.start_waiting(peer, id, file).await;
        }
        // R24-P1-2: Validate upload metadata (`id`, `token`, `key`, `chunks`) BEFORE checking,
        // caching the file handle, or announcing so a malformed empty-token `UPLOAD_STATE_STARTED`
        // record with valid `prefix_hash` can never announce and flush a dead pointer to the peer.
        if let Err(e) = upload_of(&pending) {
            if self.is_live(vgen) && !self.is_cancelled(&id) {
                self.show_upload(&peer, &pending, UploadState::Paused(e.clone()));
            }
            return Err(e);
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
        // R12-P1-4 + R13-P2-1: If this upload had 0 chunks uploaded before a reload (whether
        // saved as `UPLOAD_STATE_ANNOUNCED` or interrupted in `UPLOAD_STATE_STARTED` after
        // `inner.add`), `Engine::flush` held its outbox announcement until the file was re-attached
        // above. Flush now that `self.uploads` holds the file handle before chunk upload begins.
        if before_announce.uploaded == 0
            && self.is_live(vgen)
            && !self.is_cancelled(&id)
            && let Err(e) = self.flush(&peer).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
        let result = self.run_upload(peer, pending, file, resume).await;
        drop(running_guard);
        result
    }

    /// Settle the local vault/outbox state for a cancelled upload under held `peer_flush_lock` and
    /// `Engine::inner`, returning deferred server-delete jobs and whether the peer outbox should
    /// flush afterward (`R15-P2-7`, `R15-P2-8`, `R16-P2-7`, `R16-P2-8`, `R16-P2-9`).
    pub(super) async fn settle_cancelled_upload_locked(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        id: [u8; 16],
    ) -> Result<(Vec<ServerDeleteJob>, bool), String> {
        // R15-P2-7 + R21-P2-7 + R22-P2-9: Route `Error::Corrupt` AND malformed started
        // `PendingUpload` records (including `UPLOAD_STATE_STARTED` / `UPLOAD_STATE_ANNOUNCED`
        // rows whose upload token was emptied or corrupted so `upload_of` fails) into the
        // recovery path below while retaining any valid 32-byte `pending.key` as a delete-key
        // fallback (even for unannounced `STARTED` uploads that have no history row yet).
        let mut malformed_pending = false;
        let mut malformed_delete_key: Option<(String, [u8; attachment::KEY_LENGTH])> = None;
        let pending = match inner.vault.upload(peer, &id).await {
            _ if !self.is_live(vgen) => return Err("locked".into()),
            Ok(Some(pending)) if pending.has_started_state() && upload_of(&pending).is_err() => {
                malformed_pending = true;
                if let Ok(key) = <[u8; attachment::KEY_LENGTH]>::try_from(pending.key.as_slice()) {
                    malformed_delete_key = Some((pending.name.clone(), key));
                }
                None
            }
            Ok(pending) => pending,
            Err(crate::vault::Error::Corrupt(_)) => None,
            Err(e) => return Err(describe(&e)),
        };
        // One that waited for a sign-in never went: its message fails only if that outbox entry
        // still awaits an upload (a stale unstarted record left behind after `start_waiting`
        // promoted the message must only be forgotten, without failing the active message).
        if let Some(waiting) = pending
            .as_ref()
            .filter(|pending| !pending.has_started_state())
        {
            let still_awaits = inner.contact(peer).is_some_and(|contact| {
                contact.state.outbox.iter().any(|o| {
                    o.history_index == waiting.history_index
                        && o.awaits_upload
                        && (o.attachment_id.is_empty() || o.attachment_id == waiting.id)
                })
            });
            if still_awaits {
                self.fail_waiting(inner, peer, waiting.history_index)
                    .await?;
                if !self.is_live(vgen) {
                    return Err("locked".into());
                }
            } else {
                self.release(peer, waiting.history_index);
            }
            inner
                .vault
                .forget_upload(peer, &id)
                .await
                .map_err(|e| describe(&e))?;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            return Ok((Vec::new(), still_awaits));
        }
        let Some(pending) = pending else {
            // R14-P2-3: Even if the separate `PendingUpload` record is missing or corrupt,
            // clean up any orphaned tracked upload checkpoint and its un-dispatched outbox
            // head so subsequent messages to `peer` are never permanently wedged.
            let orphan_cp = inner
                .vault
                .tracked_upload_checkpoints(Some(peer))
                .into_iter()
                .find(|cp| cp.id.as_slice() == id.as_slice());
            let Some(cp) = orphan_cp else {
                // R15-P2-8 + R16-P2-8 + R17-P2-6: If `run_upload` finished `forget_upload` while
                // Cancel was waiting for `self.inner`, neither `PendingUpload` nor its checkpoint
                // remains, yet the completed file may still be downloadable on the server. Locate
                // its outgoing pointer in history (scanning around unrelated corrupt rows) or a
                // surviving unsealed `OutgoingRecord`, fail any un-dispatched outbox item, and
                // schedule `DeleteCompleted` using its delete key.
                let mut delete_jobs = Vec::new();
                let mut should_flush = false;
                let mut outbox_match = inner.contact(peer).and_then(|c| {
                    c.state
                        .outbox
                        .iter()
                        .find(|o| o.attachment_id.as_slice() == id.as_slice())
                        .map(|o| (o.history_index, o.dispatched, o.sealed))
                });
                let hint_idx = outbox_match.map(|(idx, _, _)| idx);
                match inner
                    .find_attachment_entry(peer, hint_idx, &id, Some(true))
                    .await
                {
                    _ if !self.is_live(vgen) => return Err("locked".into()),
                    Ok(Some((idx, entry))) => {
                        if outbox_match.is_none() {
                            outbox_match = inner.contact(peer).and_then(|contact| {
                                contact
                                    .state
                                    .outbox
                                    .iter()
                                    .find(|o| o.history_index == idx)
                                    .map(|o| (o.history_index, o.dispatched, o.sealed))
                            });
                        }
                        if !entry.gone
                            && let Some(Kind::Attachment(ptr)) =
                                entry.content.as_ref().and_then(|c| c.kind.as_ref())
                            && let Ok(key) = <[u8; 32]>::try_from(ptr.key.as_slice())
                        {
                            delete_jobs.push(ServerDeleteJob {
                                server: inner.server.clone(),
                                id,
                                history_index: Some(idx),
                                name: ptr.name.clone(),
                                kind: ServerDeleteKind::DeleteCompleted(key.into()),
                            });
                        }
                    }
                    Ok(_) | Err(crate::vault::Error::Corrupt(_)) => {}
                    Err(e) => return Err(describe(&e)),
                }
                if delete_jobs.is_empty()
                    && let Some((idx, _, false)) = outbox_match
                {
                    match inner.vault.outgoing(peer, idx).await {
                        _ if !self.is_live(vgen) => return Err("locked".into()),
                        Ok(rec) => {
                            if let Some(Kind::Attachment(ptr)) = Kind::from_bytes(&rec.content)
                                && ptr.id.as_slice() == id.as_slice()
                                && let Ok(key) = <[u8; 32]>::try_from(ptr.key.as_slice())
                            {
                                delete_jobs.push(ServerDeleteJob {
                                    server: inner.server.clone(),
                                    id,
                                    history_index: Some(idx),
                                    name: ptr.name.clone(),
                                    kind: ServerDeleteKind::DeleteCompleted(key.into()),
                                });
                            }
                        }
                        Err(crate::vault::Error::Corrupt(_)) => {}
                        Err(e) => return Err(describe(&e)),
                    }
                }
                if delete_jobs.is_empty()
                    && let Some((name, key)) = malformed_delete_key.take()
                {
                    delete_jobs.push(ServerDeleteJob {
                        server: inner.server.clone(),
                        id,
                        history_index: outbox_match.map(|(idx, _, _)| idx),
                        name,
                        kind: ServerDeleteKind::DeleteCompleted(key.into()),
                    });
                }
                let mut forgot_upload = false;
                if let Some((idx, dispatched, _)) = outbox_match {
                    if !dispatched {
                        if malformed_pending {
                            self.fail_outbox_and_forget_upload(vgen, inner, peer, idx, &id, false)
                                .await?;
                            forgot_upload = true;
                        } else {
                            self.fail_waiting(inner, peer, idx).await?;
                            if !self.is_live(vgen) {
                                return Err("locked".into());
                            }
                        }
                    }
                    should_flush = true;
                }
                if malformed_pending && !forgot_upload {
                    inner
                        .vault
                        .forget_upload(peer, &id)
                        .await
                        .map_err(|e| describe(&e))?;
                    if !self.is_live(vgen) {
                        return Err("locked".into());
                    }
                }
                return Ok((delete_jobs, should_flush));
            };
            // R16-P2-7 + R16-P2-8 + R17-P2-6: Match `WAITING` / `ANNOUNCED` checkpoints at every
            // valid index (including index `0`) and resolve the outgoing pointer delete key from
            // history or a surviving unsealed `OutgoingRecord` so already-uploaded R2 chunks are
            // deleted via `DeleteCompleted` even when `PendingUpload` or history is corrupt.
            let mut outbox_match = inner.contact(peer).and_then(|c| {
                c.state
                    .outbox
                    .iter()
                    .find(|o| super::checkpoint_matches_outbox(&cp, &id, o))
                    .map(|o| (o.history_index, o.dispatched, o.sealed))
            });
            let hint_idx = (cp.upload_state == crate::vault::UPLOAD_STATE_ANNOUNCED)
                .then_some(cp.history_index)
                .or_else(|| outbox_match.map(|(idx, _, _)| idx));
            let mut delete_jobs = Vec::new();
            match inner
                .find_attachment_entry(peer, hint_idx, &id, Some(true))
                .await
            {
                _ if !self.is_live(vgen) => return Err("locked".into()),
                Ok(Some((idx, entry))) => {
                    if outbox_match.is_none() {
                        outbox_match = inner.contact(peer).and_then(|c| {
                            c.state
                                .outbox
                                .iter()
                                .find(|o| o.history_index == idx)
                                .map(|o| (o.history_index, o.dispatched, o.sealed))
                        });
                    }
                    if !entry.gone
                        && let Some(Kind::Attachment(ptr)) =
                            entry.content.as_ref().and_then(|c| c.kind.as_ref())
                        && let Ok(key) = <[u8; 32]>::try_from(ptr.key.as_slice())
                    {
                        delete_jobs.push(ServerDeleteJob {
                            server: inner.server.clone(),
                            id,
                            history_index: Some(idx),
                            name: ptr.name.clone(),
                            kind: ServerDeleteKind::DeleteCompleted(key.into()),
                        });
                    }
                }
                Ok(_) | Err(crate::vault::Error::Corrupt(_)) => {}
                Err(e) => return Err(describe(&e)),
            }
            if delete_jobs.is_empty()
                && let Some((idx, _, false)) = outbox_match
            {
                match inner.vault.outgoing(peer, idx).await {
                    _ if !self.is_live(vgen) => return Err("locked".into()),
                    Ok(rec) => {
                        if let Some(Kind::Attachment(ptr)) = Kind::from_bytes(&rec.content)
                            && ptr.id.as_slice() == id.as_slice()
                            && let Ok(key) = <[u8; 32]>::try_from(ptr.key.as_slice())
                        {
                            delete_jobs.push(ServerDeleteJob {
                                server: inner.server.clone(),
                                id,
                                history_index: Some(idx),
                                name: ptr.name.clone(),
                                kind: ServerDeleteKind::DeleteCompleted(key.into()),
                            });
                        }
                    }
                    Err(crate::vault::Error::Corrupt(_)) => {}
                    Err(e) => return Err(describe(&e)),
                }
            }
            if delete_jobs.is_empty()
                && let Some((name, key)) = malformed_delete_key.take()
            {
                delete_jobs.push(ServerDeleteJob {
                    server: inner.server.clone(),
                    id,
                    history_index: outbox_match.map(|(idx, _, _)| idx),
                    name,
                    kind: ServerDeleteKind::DeleteCompleted(key.into()),
                });
            }
            let mut should_flush = false;
            let mut forgot_upload = false;
            if let Some((idx, dispatched, _)) = outbox_match {
                if !dispatched {
                    // R18-P2-4: Atomically remove the outbox entry, mark history refused, delete
                    // `OutgoingRecord`, and forget the upload checkpoint in ONE vault transaction
                    // so a transient `forget_upload` error can never lose the sole surviving
                    // `DeleteCompleted` key before retry.
                    self.fail_outbox_and_forget_upload(vgen, inner, peer, idx, &id, false)
                        .await?;
                    forgot_upload = true;
                }
                should_flush = true;
            }
            if !forgot_upload {
                inner
                    .vault
                    .forget_upload(peer, &id)
                    .await
                    .map_err(|e| describe(&e))?;
                if !self.is_live(vgen) {
                    return Err("locked".into());
                }
            }
            return Ok((delete_jobs, should_flush));
        };
        let upload = upload_of(&pending)?;
        // R17-P2-5 + R23-P2-2: Match `Outgoing.attachment_id` as well as
        // `pending.has_announced_state()` so a valid `STARTED` upload whose `ANNOUNCED` save
        // failed AND whose `HistoryEntry` is missing/corrupt still settles its un-dispatched
        // outbox head before forgetting.
        let mut announced_index = pending
            .has_announced_state()
            .then_some(pending.history_index)
            .or_else(|| {
                inner.contact(peer).and_then(|c| {
                    c.state
                        .outbox
                        .iter()
                        .find(|o| o.attachment_id.as_slice() == id.as_slice())
                        .map(|o| o.history_index)
                })
            });
        if announced_index.is_none() {
            match inner
                .find_attachment_entry(peer, None, &id, Some(true))
                .await
            {
                _ if !self.is_live(vgen) => return Err("locked".into()),
                Ok(Some((idx, _))) => {
                    announced_index = Some(idx);
                }
                Ok(_) | Err(crate::vault::Error::Corrupt(_)) => {}
                Err(e) => return Err(describe(&e)),
            }
        }
        let mut should_flush = false;
        let mut forgot_upload = false;
        let mut extra_server_deletes = Vec::new();
        if let Some(idx) = announced_index {
            let relayed_commit = inner
                .in_flight_push
                .get(peer)
                .copied()
                .filter(|f| f.relayed && f.history_index == idx)
                .and_then(|relayed| {
                    let c = inner.contacts.iter().find(|c| c.peer == *peer)?;
                    if c.state.conversation_gen != relayed.conversation_gen {
                        return None;
                    }
                    let head = c.state.outbox.first()?;
                    if head.history_index == relayed.history_index
                        && head.sealed
                        && head.clock == relayed.clock
                    {
                        let confirm_session = !c.session.needs_new_session()
                            && !c.state.needs_requeue_sealed
                            && (relayed.session_id.is_none()
                                || c.session.active_id() == relayed.session_id.as_ref());
                        Some((head.clone(), confirm_session))
                    } else {
                        None
                    }
                });
            if let Some((head, confirm_session)) = relayed_commit {
                // The announcement already reached the relay (`relayed == true`) and only
                // lacked local commit: settle it as `Step::Pushed` (retaining receipt tracking
                // and releasing the send slot) rather than rewriting it to `Step::Refused`.
                match self
                    .commit_outbox_item(
                        vgen,
                        inner,
                        peer,
                        &head,
                        Step::Pushed,
                        head.clock,
                        confirm_session,
                        &mut extra_server_deletes,
                    )
                    .await
                {
                    Ok(super::outbox::CommitOutcome::Committed) => {
                        inner.in_flight_push.remove(peer);
                        self.clear_approval_backoff(peer);
                        self.release(peer, head.history_index);
                        should_flush = true;
                    }
                    Ok(super::outbox::CommitOutcome::Aborted) => return Err("locked".into()),
                    Err(e) => return Err(e),
                }
            } else {
                let outbox_state = inner.contact(peer).and_then(|contact| {
                    contact
                        .state
                        .outbox
                        .iter()
                        .find(|outgoing| outgoing.history_index == idx)
                        .map(|outgoing| outgoing.dispatched)
                });
                match outbox_state {
                    Some(false) => {
                        // Never transmitted on the wire: atomically fail/drop from outbox and
                        // forget the upload record in one transaction.
                        self.fail_outbox_and_forget_upload(vgen, inner, peer, idx, &id, false)
                            .await?;
                        forgot_upload = true;
                        should_flush = true;
                    }
                    Some(true) => {
                        // Previously dispatched with an ambiguous outcome (e.g. lost response
                        // or reload): keep the sealed head in the outbox so the subsequent
                        // `flush` reconciles its exact `client_message_id` idempotently rather
                        // than falsely marking an already-delivered announcement as `Refused`.
                        should_flush = true;
                    }
                    None => {}
                }
            }
        }
        if !forgot_upload {
            inner
                .vault
                .forget_upload(peer, &id)
                .await
                .map_err(|e| describe(&e))?;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
        }
        let job = ServerDeleteJob {
            server: inner.server.clone(),
            id,
            history_index: announced_index,
            name: pending.name.clone(),
            kind: ServerDeleteKind::CancelUpload(upload),
        };
        extra_server_deletes.push(job);
        Ok((extra_server_deletes, should_flush))
    }

    /// Stop the upload `id`, in the chat with `peer`, and forget it. The server deletes what it
    /// has, so the peer finds the attachment gone; if it cannot be reached, what it has expires.
    pub async fn cancel_upload(&self, peer: PublicKey, id: [u8; 16]) -> Result<(), String> {
        let vgen = self.vault_gen();
        // For good, running or not: what is on its way stops immediately, even if a peer flush is
        // currently awaiting a `PushV2` RTT before we serialize outbox settlement below.
        // R16-P2-9: Track in `pending_cancellations` until local vault settlement commits so a
        // transient IDB error never strands the peer's outbox with no UI card left to retry.
        self.uploads.mark_cancelled(id);
        self.uploads.insert_pending_cancel(peer, id);
        self.uploads.clear_server_completed(&id);
        self.remove_attachment_caches(&peer, &id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        // Serialize outbox/announcement settlement behind any in-flight `Engine::flush(&peer)`
        // (preserving `peer_flush_lock -> self.inner`) so an already-accepted announcement whose
        // `PushV2` response is in flight is settled as `Step::Pushed` instead of `Step::Refused`.
        let peer_lock = self.queue.peer_flush_lock(&peer);
        let peer_guard = peer_lock.lock().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let (delete_jobs, should_flush) = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let settled = self
                .settle_cancelled_upload_locked(vgen, inner, &peer, id)
                .await?;
            self.uploads.remove_pending_cancel(&peer, &id);
            settled
        };
        drop(peer_guard);
        // Perform the HTTP cancel/delete outside `self.inner.lock()` and `peer_flush_lock` so slow
        // deletes never block the UI and `self.flush(&peer)` can re-acquire cleanly.
        if !delete_jobs.is_empty() {
            self.finish_server_deletes(&peer, delete_jobs).await;
        }
        if should_flush && self.is_live(vgen) {
            // R25-P1-1 + R25-P2-1: Clear any stale peer sign-in wait held by the cancelled upload
            // so the next queued message attempts delivery or gets marked in `ui.held`, while
            // flushing in background mode so cancelling an upload never pops `Dialog::SignIn`
            // after the user declined sign-in or during an active `start_chat`.
            self.queue.clear_peer_sign_in_wait(&peer);
            if let Err(e) = self.flush_background(&peer).await
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
    /// Cancel a message held for sign-in, pinned to `expected_conversation_gen` so a stale click
    /// cannot fail a message at the same reused `history_index` in a recreated conversation.
    pub async fn cancel_held_for_gen(
        &self,
        peer: PublicKey,
        index: u64,
        expected_conversation_gen: u64,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let waiting = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_ref().ok_or("locked")?;
            let current_gen = inner
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .map(|c| c.state.conversation_gen);
            if current_gen != Some(expected_conversation_gen) {
                return Err("chat changed; please retry.".to_string());
            }
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
                (!pending.has_started_state() && pending.history_index == index)
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
        let peer_lock = self.queue.peer_flush_lock(&peer);
        let peer_guard = peer_lock.lock().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let server_deletes = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let current_gen = inner
                .contacts
                .iter()
                .find(|c| c.peer == peer)
                .map(|c| c.state.conversation_gen);
            if current_gen != Some(expected_conversation_gen) {
                return Err("chat changed; please retry.".to_string());
            }
            let relayed_commit = inner
                .in_flight_push
                .get(&peer)
                .copied()
                .filter(|f| f.relayed && f.history_index == index)
                .and_then(|relayed| {
                    let c = inner.contacts.iter().find(|c| c.peer == peer)?;
                    if c.state.conversation_gen != relayed.conversation_gen {
                        return None;
                    }
                    let head = c.state.outbox.first()?;
                    if head.history_index == relayed.history_index
                        && head.sealed
                        && head.clock == relayed.clock
                    {
                        let confirm_session = !c.session.needs_new_session()
                            && !c.state.needs_requeue_sealed
                            && (relayed.session_id.is_none()
                                || c.session.active_id() == relayed.session_id.as_ref());
                        Some((head.clone(), confirm_session))
                    } else {
                        None
                    }
                });
            if let Some((head, confirm_session)) = relayed_commit {
                let mut extra_deletes = Vec::new();
                match self
                    .commit_outbox_item(
                        vgen,
                        inner,
                        &peer,
                        &head,
                        Step::Pushed,
                        head.clock,
                        confirm_session,
                        &mut extra_deletes,
                    )
                    .await
                {
                    Ok(super::outbox::CommitOutcome::Committed) => {
                        inner.in_flight_push.remove(&peer);
                        self.clear_approval_backoff(&peer);
                        self.release(&peer, head.history_index);
                        extra_deletes
                    }
                    Ok(super::outbox::CommitOutcome::Aborted) => return Err("locked".into()),
                    Err(e) => return Err(e),
                }
            } else {
                // Gone meanwhile, e.g. pushed as the sign-in came.
                let outbox_state = inner.contact(&peer).and_then(|contact| {
                    contact
                        .state
                        .outbox
                        .iter()
                        .find(|outgoing| outgoing.history_index == index)
                        .map(|outgoing| outgoing.dispatched)
                });
                match outbox_state {
                    None => {
                        self.release(&peer, index);
                        return Ok(());
                    }
                    Some(true) => {
                        return Err(
                            "This message was already sent to the server before sign-in expired; \
                             sign in to confirm delivery rather than cancelling it."
                                .into(),
                        );
                    }
                    Some(false) => {
                        self.fail_waiting(inner, &peer, index).await?;
                        self.prepare_cancel_uploads_for_failed(inner, &peer, &[index])
                            .await
                    }
                }
            }
        };
        drop(peer_guard);
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
        // R25-P2-1: Flush the next message in background mode so cancelling a held message does
        // not pop `Dialog::SignIn` after the user declined sign-in, while still marking the next
        // head in `ui.held` on 403.
        if let Err(e) = self.flush_background(&peer).await
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
                (pending.has_announced_state() || !pending.has_started_state())
                    .then_some(pending.history_index)
                    .filter(|idx| failed_indices.contains(idx))
            });
            if matched_index.is_none() && !by_id.contains_key(&id) {
                continue;
            }
            self.uploads.mark_cancelled(id);
            self.uploads.clear_server_completed(&id);
            self.remove_attachment_caches(peer, &id);
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|item| item.id != id));
            if pending.has_started_state() {
                if let Ok(upload) = upload_of(&pending) {
                    handled_ids.insert(id);
                    jobs.push(ServerDeleteJob {
                        server: server.clone(),
                        id,
                        history_index: matched_index,
                        name: pending.name.clone(),
                        kind: ServerDeleteKind::CancelUpload(upload),
                    });
                } else if let Some(key) =
                    copy_zeroizing_array::<{ attachment::KEY_LENGTH }>(&pending.key)
                {
                    // R23-P2-2: Malformed `STARTED`/`ANNOUNCED` record (e.g. empty upload token)
                    // still carries its 32-byte delete key: enqueue `DeleteCompleted` directly
                    // before forgetting the record instead of treating it as unstarted.
                    handled_ids.insert(id);
                    jobs.push(ServerDeleteJob {
                        server: server.clone(),
                        id,
                        history_index: matched_index,
                        name: pending.name.clone(),
                        kind: ServerDeleteKind::DeleteCompleted(key),
                    });
                }
                // If neither `upload_of(&pending)` nor `pending.key` is usable, leave `id` out of
                // `handled_ids` so the `by_id` pass below can still attempt `attachment::delete`
                // via `pointer.key`.
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
            self.uploads.clear_server_completed(&id);
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
            if self.is_cancelled(&id) {
                self.uploads.clear_server_completed(&id);
            }
            return Ok(());
        }
        match uploaded {
            Ok(true) => {}
            // Deleted from the server, e.g. by the peer, who did not want it: the rest need not
            // go up.
            Ok(false) => {
                let hint = pending
                    .has_announced_state()
                    .then_some(pending.history_index);
                let drop_res = self.drop_upload(&peer, id, hint).await;
                if pending.has_announced_state() && self.is_live(vgen) {
                    let _ = self
                        .note_gone_by_id(&peer, Some(pending.history_index), &id)
                        .await;
                }
                drop_res?;
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
                    self.uploads.clear_server_completed(&id);
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
        // Forgotten, with its upload token, which is no use now: deleting it takes its delete
        // token, which its key gives.
        // R14-P2-1: Complete `forget_upload` BEFORE removing the local file handle and UI row so a
        // concurrent `Engine::flush` on a `<= CHUNK_SIZE` (0-checkpoint-chunks) upload or a
        // transient IndexedDB error never stalls or permanently wedges `peer`'s outbox.
        let guard = self.lock_inner().await;
        if !self.is_live(vgen) {
            return Ok(());
        }
        let inner = guard.as_ref().ok_or("locked")?;
        if let Err(e) = inner.vault.forget_upload(&peer, &id).await {
            let err = describe(&e);
            if self.is_live(vgen) {
                // R19-P2-4: Schedule `restore_uploads_from_vault()` in `sync()` so once storage
                // recovers the completed vault record, cached file, and paused UI card clear
                // automatically instead of remaining stranded until reload.
                self.uploads.set_restore_needed(true);
                self.show_upload(&peer, &pending, UploadState::Paused(err.clone()));
            }
            drop(guard);
            if self.is_live(vgen) {
                self.wake();
            }
            return Err(err);
        }
        self.uploads.clear_server_completed(&id);
        self.remove_attachment_caches(&peer, &id);
        if self.is_live(vgen) {
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|upload| upload.id != id));
        }
        drop(guard);
        if self.is_live(vgen) {
            self.wake();
        }
        Ok(())
    }

    /// Atomically remove an un-dispatched attachment outbox item, mark its history entry refused
    /// (and optionally `gone`), delete its `OutgoingRecord`, and forget the upload/checkpoint in
    /// one vault transaction (`R18-P1-3`, `R18-P2-4`).
    pub(super) async fn fail_outbox_and_forget_upload(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        idx: u64,
        id: &[u8; 16],
        mark_gone: bool,
    ) -> Result<(), String> {
        let changed = inner
            .with_contact_tx(peer, async |inner| {
                let mut hist = Vec::new();
                let mut expires = 0u64;
                match inner.vault.entry(peer, idx).await {
                    Ok(Some(mut entry)) => {
                        if let Some(Kind::Attachment(ptr)) =
                            entry.content.as_ref().and_then(|c| c.kind.as_ref())
                        {
                            expires = ptr.expires;
                        }
                        entry.set_delivery(entry.delivery().after(Step::Refused));
                        if mark_gone {
                            entry.gone = true;
                        }
                        hist.push((idx, entry));
                    }
                    Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {}
                    Err(e) => return Err(describe(&e)),
                }
                let server_now = inner.client.clock().now();
                if let Some(contact) = inner.contact(peer) {
                    contact.state.outbox.retain(|o| o.history_index != idx);
                    if mark_gone {
                        contact.record_deleted_attachment(id, expires, server_now);
                    }
                }
                inner
                    .promote_upload_with(
                        peer,
                        id,
                        None,
                        &records(peer, &hist),
                        &[(*peer, idx, None)],
                    )
                    .await
                    .map_err(|e| describe(&e))?;
                Ok(hist)
            })
            .await?;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        self.release(peer, idx);
        if mark_gone {
            self.ui.gone.update(|gone| {
                gone.insert((*peer, idx));
            });
        }
        if !changed.is_empty() {
            self.show_changes(inner, peer, &changed);
        }
        Ok(())
    }

    /// Stop the upload `id`, in the chat with `peer`, if this client uploads it, for good, as
    /// the server no longer has it, settle any un-dispatched outbox announcement atomically under
    /// `peer_flush_lock`, and forget it (`R18-P1-3`).
    async fn drop_upload(
        &self,
        peer: &PublicKey,
        id: [u8; 16],
        hint_index: Option<u64>,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        // Mark cancelled and drop UI/caches immediately before acquiring `peer_flush_lock` so any
        // concurrent upload task or `Engine::flush` stops before transmitting a dead pointer.
        self.uploads.mark_cancelled(id);
        self.uploads.clear_server_completed(&id);
        self.remove_attachment_caches(peer, &id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        let peer_lock = self.queue.peer_flush_lock(peer);
        let peer_guard = peer_lock.lock().await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let settled_outbox = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let cp = inner
                .vault
                .tracked_upload_checkpoints(Some(peer))
                .into_iter()
                .find(|cp| cp.id.as_slice() == id.as_slice());
            let has_upload = match inner.vault.upload(peer, &id).await {
                _ if !self.is_live(vgen) => return Err("locked".into()),
                Ok(Some(_)) | Err(crate::vault::Error::Corrupt(_)) => true,
                Ok(None) => cp.is_some(),
                Err(e) => {
                    self.uploads.insert_pending_cancel(*peer, id);
                    return Err(describe(&e));
                }
            };
            let mut outbox_match = inner.contact(peer).and_then(|c| {
                c.state
                    .outbox
                    .iter()
                    .find(|o| {
                        o.attachment_id.as_slice() == id.as_slice()
                            || cp
                                .as_ref()
                                .is_some_and(|cp| super::checkpoint_matches_outbox(cp, &id, o))
                    })
                    .map(|o| (o.history_index, o.dispatched))
            });
            if outbox_match.is_none()
                && inner
                    .contact(peer)
                    .is_some_and(|c| !c.state.outbox.is_empty())
            {
                let effective_hint = hint_index.or_else(|| {
                    cp.as_ref()
                        .filter(|cp| cp.upload_state == crate::vault::UPLOAD_STATE_ANNOUNCED)
                        .map(|cp| cp.history_index)
                });
                match inner
                    .find_attachment_entry(peer, effective_hint, &id, Some(true))
                    .await
                {
                    _ if !self.is_live(vgen) => return Err("locked".into()),
                    Ok(Some((idx, _))) => {
                        outbox_match = inner.contact(peer).and_then(|c| {
                            c.state
                                .outbox
                                .iter()
                                .find(|o| o.history_index == idx)
                                .map(|o| (o.history_index, o.dispatched))
                        });
                    }
                    Ok(None) | Err(crate::vault::Error::Corrupt(_)) => {}
                    Err(e) => {
                        self.uploads.insert_pending_cancel(*peer, id);
                        return Err(describe(&e));
                    }
                }
            }
            if let Some((idx, false)) = outbox_match {
                if let Err(e) = self
                    .fail_outbox_and_forget_upload(vgen, inner, peer, idx, &id, true)
                    .await
                {
                    if self.is_live(vgen) {
                        self.uploads.insert_pending_cancel(*peer, id);
                    }
                    return Err(e);
                }
                self.uploads.remove_pending_cancel(peer, &id);
                true
            } else {
                if has_upload {
                    if let Err(e) = inner.vault.forget_upload(peer, &id).await {
                        if self.is_live(vgen) {
                            self.uploads.insert_pending_cancel(*peer, id);
                        }
                        return Err(describe(&e));
                    }
                    if !self.is_live(vgen) {
                        return Err("locked".into());
                    }
                }
                self.uploads.remove_pending_cancel(peer, &id);
                outbox_match.is_some()
            }
        };
        drop(peer_guard);
        if settled_outbox && self.is_live(vgen) {
            self.wake();
        }
        Ok(())
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
        // R21-P2-9: Always invoke `note_gone` after confirmed server deletion even if
        // `drop_upload` hits a transient storage error so incoming attachments are still marked
        // `gone = true` (or queued in `pending_gone` for sync retry).
        let drop_res = self.drop_upload(&peer, id, Some(index)).await;
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let gone_res = self.note_gone(&peer, index, &id).await;
        drop_res?;
        gone_res
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
        self.note_gone_by_id_for_gen(peer, hint_index, id, None)
            .await
    }

    pub(super) async fn note_gone_by_id_for_gen(
        &self,
        peer: &PublicKey,
        hint_index: Option<u64>,
        id: &[u8; 16],
        expected_gen: Option<u64>,
    ) -> Result<(), String> {
        self.note_gone_by_id_for_gen_with_wake(peer, hint_index, id, expected_gen, true)
            .await
    }

    pub(super) async fn note_gone_by_id_for_gen_with_wake(
        &self,
        peer: &PublicKey,
        hint_index: Option<u64>,
        id: &[u8; 16],
        expected_gen: Option<u64>,
        wake_on_err: bool,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        let res = {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let Some(conv_gen) = inner
                .contacts
                .iter()
                .find(|c| c.peer == *peer)
                .map(|c| c.state.conversation_gen)
            else {
                if let Some(expected) = expected_gen {
                    self.uploads.remove_pending_gone(peer, expected, id);
                }
                return Ok(());
            };
            if let Some(expected) = expected_gen
                && conv_gen != expected
            {
                self.uploads.remove_pending_gone(peer, expected, id);
                return Ok(());
            }
            let inner_res = self
                .note_gone_inner(vgen, inner, peer, hint_index, id)
                .await;
            (conv_gen, inner_res)
        };
        let (conv_gen, inner_res) = res;
        match inner_res {
            Ok(()) => {
                self.uploads.remove_pending_gone(peer, conv_gen, id);
                Ok(())
            }
            Err(e) => {
                if self.is_live(vgen) {
                    // R20-P2-8 + R21-P2-11: Queue failed `HistoryEntry.gone = true` saves for
                    // retry in `sync()` and exclude the deleted pointer from unread requeue until
                    // storage recovers. Only call `self.wake()` for foreground triggers so a
                    // persistent storage error does not disable background polling backoff.
                    self.uploads.insert_pending_gone(*peer, conv_gen, *id);
                    if wake_on_err {
                        self.wake();
                    }
                }
                Err(e)
            }
        }
    }

    pub(super) async fn note_gone_inner(
        &self,
        vgen: u64,
        inner: &mut Inner<V>,
        peer: &PublicKey,
        hint_index: Option<u64>,
        id: &[u8; 16],
    ) -> Result<(), String> {
        // R21-P2-10 + R21-P3-3 + R22-P2-10 + R23-P2-3: Record `id` in
        // `ContactState.deleted_attachments` FIRST (before `find_all_attachment_entries`) using
        // `server_now` from `ServerClock`, with `expires = 0` (unexpirable) until every matching
        // `HistoryEntry.gone = true` is confirmed persisted.
        let server_now = inner.client.clock().now();
        let mut recorded_deleted = inner
            .contact(peer)
            .is_some_and(|contact| contact.record_deleted_attachment(id, 0, server_now));
        // R19-P2-3 + R20-P3-2: Locate EVERY history entry carrying attachment `id` (both the
        // original outgoing message and any reflected incoming echo(es)) so deleting from either
        // direction marks all matching rows `gone = true` atomically in one save.
        let to_mark = match inner
            .find_all_attachment_entries(peer, hint_index, id)
            .await
        {
            Ok(entries) => entries,
            Err(e) => {
                // R24-P2-3: Always persist `expires = 0` when clearing an existing non-zero
                // tombstone expiry even if `record_deleted_attachment(id, 0, server_now)` returned
                // `false` because `id` was already present.
                let cleared_expiry = inner
                    .contact(peer)
                    .is_some_and(|contact| contact.clear_deleted_attachment_expiry(id));
                if recorded_deleted || cleared_expiry {
                    inner.unsaved_state = true;
                    if inner.save_state().await.is_ok() {
                        inner.unsaved_state = false;
                    }
                }
                return Err(describe(&e));
            }
        };
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        let max_expires = to_mark
            .iter()
            .filter_map(
                |(_, entry)| match entry.content.as_ref().and_then(|c| c.kind.as_ref()) {
                    Some(Kind::Attachment(ptr)) if ptr.expires > 0 => Some(ptr.expires),
                    _ => None,
                },
            )
            .max()
            .unwrap_or(0);
        if to_mark.is_empty() {
            if recorded_deleted && let Err(e) = inner.save_state().await {
                inner.unsaved_state = true;
                return Err(describe(&e));
            }
            return Ok(());
        }
        let marked_indices: Vec<u64> = to_mark.iter().map(|(index, _)| *index).collect();
        let mut to_save: Vec<(u64, crate::vault::HistoryEntry)> = Vec::new();
        for (index, mut entry) in to_mark {
            if !entry.gone {
                entry.gone = true;
                to_save.push((index, entry));
            }
        }
        if max_expires > 0
            && inner.contact(peer).is_some_and(|contact| {
                contact.record_deleted_attachment(id, max_expires, server_now)
            })
        {
            recorded_deleted = true;
        }
        // R20-P2-8 + R23-P2-3: Persist `gone = true` durably BEFORE flipping `self.ui.gone` so a
        // transient storage error never hides the delete control while leaving `gone = false` on
        // disk. If saving `HistoryEntry` fails, revert the tombstone's `expires` to `0`
        // (unexpirable) before persisting `AppState` so post-expiry pruning can never drop the
        // tombstone while `HistoryEntry.gone` is still `false`.
        if !to_save.is_empty() {
            if let Err(e) = inner.save(&records(peer, &to_save)).await {
                if let Some(contact) = inner.contact(peer) {
                    contact.clear_deleted_attachment_expiry(id);
                }
                inner.unsaved_state = true;
                if inner.save_state().await.is_ok() {
                    inner.unsaved_state = false;
                }
                return Err(describe(&e));
            }
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
        } else if recorded_deleted {
            if let Err(e) = inner.save_state().await {
                inner.unsaved_state = true;
                return Err(describe(&e));
            }
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
        }
        self.ui.gone.update(|gone| {
            for index in &marked_indices {
                gone.insert((*peer, *index));
            }
        });
        if !to_save.is_empty() {
            self.show_changes(inner, peer, &to_save);
        }
        Ok(())
    }

    /// Upload the chunks of `pending` from `uploaded` on, encrypting any already-verified resumed
    /// chunk directly from `verified_chunks` and reading newer chunks from `file` in turn, unless
    /// the upload is cancelled. Returns whether the server still has the attachment: one deleted
    /// meanwhile, e.g. by the peer, is not found.
    pub(super) async fn upload_chunks(
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
        let (server, expected_conv_gen) = {
            let guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Ok(true);
            }
            let inner = guard.as_ref().ok_or("locked")?;
            let Some(conv_gen) = inner
                .contacts
                .iter()
                .find(|c| c.peer == *peer)
                .map(|c| c.state.conversation_gen)
            else {
                return Ok(true);
            };
            (inner.server.clone(), conv_gen)
        };
        let signs_in_here = same_server(&server, &origin());
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
        let attachments = Fetch::reporting_without_refused_hook(&server, progress);
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
                .put_chunk(
                    peer,
                    pending,
                    &attachments,
                    upload,
                    index,
                    &chunk,
                    expected_conv_gen,
                    signs_in_here,
                )
                .await?
            {
                return Ok(false);
            }
            if !self.is_live(vgen) || self.is_cancelled(upload.id()) {
                self.uploads.clear_server_completed(upload.id());
                return Ok(true);
            }
            pending.uploaded = index + 1;
            let is_final = pending.uploaded >= upload.chunks();
            if is_final {
                // R20-P2-4: The server now holds every chunk of this attachment. Record completion
                // immediately so a subsequent local cache-write or `forget_upload` storage error
                // never lets `delete_inner` cancel an already-complete attachment for the peer.
                self.uploads.mark_server_completed(*peer, *upload.id());
            }
            match self
                .keep_chunk_for_gen(peer, upload.id(), index, &chunk, None)
                .await
            {
                Ok(_) => {}
                Err(e) if is_final => {
                    // Persist `uploaded == chunks` best-effort so completion also survives reload
                    // if `forget_upload` fails next; local sender caching is strictly optional once
                    // every chunk is on the server.
                    let _ = self.save_upload(peer, pending).await;
                    if self.is_live(vgen) {
                        self.ui.log(format!(
                            "uploaded {} to server, but local chunk cache write failed: {e}",
                            pending.name
                        ));
                    }
                }
                Err(e) => {
                    let _ = self.save_upload(peer, pending).await;
                    return Err(e);
                }
            }
        }
        Ok(true)
    }

    /// Upload chunk `index` of `upload`, trying again while the server cannot be reached, unless
    /// the upload is cancelled meanwhile. Returns whether the server still has the attachment.
    #[allow(clippy::too_many_arguments)]
    async fn put_chunk(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        attachments: &Connect,
        upload: &Upload,
        index: u32,
        chunk: &[u8],
        expected_conv_gen: u64,
        signs_in_here: bool,
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
                Err(e) if e.kind() == ErrorKind::SignInRequired => {
                    // R23-P2-1: Open `Dialog::SignIn` ONLY when the vault is still live, the
                    // upload is not cancelled, the server matches this origin, and the contact
                    // still exists at `expected_conv_gen`.
                    if signs_in_here && self.is_live(vgen) && !self.is_cancelled(upload.id()) {
                        let still_active = {
                            let guard = self.lock_inner().await;
                            self.is_live(vgen)
                                && !self.is_cancelled(upload.id())
                                && guard.as_ref().is_some_and(|inner| {
                                    self.may_keep_for_gen(
                                        inner,
                                        peer,
                                        upload.id(),
                                        Some(expected_conv_gen),
                                    )
                                })
                        };
                        if still_active && self.is_live(vgen) && !self.is_cancelled(upload.id()) {
                            self.ask_sign_in_background();
                        }
                    }
                    return Err(describe(&e));
                }
                Err(e) => return Err(describe(&e)),
            }
        }
    }

    /// Keep `pending`, of the chat with `peer`, in the vault, unless it was cancelled or its chat
    /// deleted meanwhile, which forgot it: it must not come back.
    async fn save_upload(&self, peer: &PublicKey, pending: &PendingUpload) -> Result<(), String> {
        self.save_upload_for_gen(peer, pending, None).await
    }

    async fn save_upload_for_gen(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        expected_gen: Option<u64>,
    ) -> Result<(), String> {
        let guard = self.lock_inner().await;
        let inner = guard.as_ref().ok_or("locked")?;
        if !self.may_keep_for_gen(inner, peer, &pending.id, expected_gen) {
            return Err(format!("the upload of {} was cancelled", pending.name));
        }
        if expected_gen.is_some()
            && inner
                .contacts
                .iter()
                .find(|c| c.peer == *peer)
                .is_some_and(|c| c.state.request || c.state.quarantined)
        {
            return Err("chat changed; please retry.".into());
        }
        inner
            .vault
            .save_upload(peer, pending)
            .await
            .map_err(|e| describe(&e))
    }

    /// Whether the vault may keep what goes with the attachment `id`, in the chat with `peer`:
    /// its upload was not cancelled, and the chat is still there (optionally pinned to
    /// `expected_gen`). Asked under the lock, which cancelling and deleting take to forget them,
    /// so that nothing is kept after.
    pub(super) fn may_keep(&self, inner: &Inner<V>, peer: &PublicKey, id: &[u8]) -> bool {
        self.may_keep_for_gen(inner, peer, id, None)
    }

    pub(super) fn may_keep_for_gen(
        &self,
        inner: &Inner<V>,
        peer: &PublicKey,
        id: &[u8],
        expected_gen: Option<u64>,
    ) -> bool {
        let cancelled = <[u8; 16]>::try_from(id).is_ok_and(|id| self.is_cancelled(&id));
        !cancelled
            && inner.contacts.iter().any(|contact| {
                contact.peer == *peer
                    && expected_gen.is_none_or(|want| contact.state.conversation_gen == want)
            })
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
        if let Err(FetchError::NotFound {
            conversation_gen, ..
        }) = &fetched
        {
            let _ = self
                .note_gone_by_id_for_gen(&peer, Some(index), &id, *conversation_gen)
                .await;
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
        if let Err(FetchError::NotFound {
            conversation_gen, ..
        }) = &fetched
        {
            let _ = self
                .note_gone_by_id_for_gen(&peer, Some(index), &id, *conversation_gen)
                .await;
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
        fetched: Result<Option<(Attachment, bool, Option<u64>)>, String>,
    ) -> Result<Option<Attachment>, String> {
        let vgen = self.vault_gen();
        let Some((attachment, from_server, conversation_gen)) = fetched? else {
            return Ok(None);
        };
        if !self.is_live(vgen) {
            return Ok(None);
        }
        if from_server
            && clock > 0
            && let Err(e) = self.downloaded_for_gen(peer, clock, conversation_gen).await
            && self.is_live(vgen)
        {
            self.ui.link.set(Link::Offline(e));
        }
        Ok(Some(attachment))
    }

    /// Tell `peer` that its attachment, sent in its message at `clock`, is downloaded, verifying
    /// `expected_gen` under `self.inner` so a stale download can never queue a receipt on a
    /// deleted-and-recreated conversation (`R8-P2-5`).
    pub(super) async fn downloaded_for_gen(
        &self,
        peer: PublicKey,
        clock: u64,
        expected_gen: Option<u64>,
    ) -> Result<(), String> {
        let vgen = self.vault_gen();
        {
            let mut guard = self.lock_inner().await;
            if !self.is_live(vgen) {
                return Err("locked".into());
            }
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            if expected_gen.is_some_and(|expected| contact.state.conversation_gen != expected) {
                return Ok(());
            }
            if contact.tell_downloaded(clock) {
                inner.save_state().await.map_err(|e| describe(&e))?;
            }
        }
        if !self.is_live(vgen) {
            return Err("locked".into());
        }
        // R25-P2-1: Downloaded receipts fire automatically after unauthenticated `GetChunk`
        // fetches (including inline media); flush in background mode so they honor
        // `declined_sign_in` and `in_flight_start_chat`.
        self.flush_background(&peer).await.map(drop)
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
    ) -> Result<Option<(Attachment, bool, Option<u64>)>, FetchError> {
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
            return Ok(Some((attachment, false, None)));
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
        Ok(Some((attachment, fetched, Some(fetching.conversation_gen))))
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
        let server_now = inner.client.clock().now();
        let (conversation_gen, deleted_in_state) = inner
            .contacts
            .iter()
            .find(|c| c.peer == peer)
            .map(|c| (c.state.conversation_gen, c.is_attachment_deleted(&id)))
            .ok_or("no such chat")?;
        let is_expired = expired(pointer, server_now);
        let entry_gone = if deleted_in_state || is_expired {
            true
        } else {
            matches!(inner.vault.entry(&peer, index).await, Ok(Some(entry)) if entry.gone)
        };
        let known_gone = deleted_in_state || entry_gone || is_expired;
        let unfinished = inner
            .vault
            .upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))?
            .map(|pending| pending.uploaded);
        Ok(Fetching {
            peer,
            conversation_gen,
            index,
            id,
            key,
            key_hash,
            name: pointer.name.clone(),
            size: pointer.size,
            chunks,
            unfinished,
            known_gone,
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
        // short-circuit immediately if already known deleted from the server (`R22-P3-3`),
        // otherwise re-fetch from the server below and repair IndexedDB via `keep_chunk`.
        if fetching.known_gone {
            return Err(FetchError::NotFound {
                message: format!("{} is gone from the server", fetching.name),
                conversation_gen: Some(fetching.conversation_gen),
            });
        }
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
                fetching.conversation_gen,
                waiter,
            )
            .await?
        else {
            return Ok(None);
        };
        let plaintext = decrypt_and_validate(&chunk)?;
        // Kept only once it decrypts, matches `expected_len`, AND belongs to the same
        // conversation generation (`R8-P2-5`), aborting cleanly if the chat was deleted/recreated.
        if !self
            .keep_chunk_for_gen(
                &fetching.peer,
                &fetching.id,
                index,
                &chunk,
                Some(fetching.conversation_gen),
            )
            .await
            .map_err(FetchError::Other)?
        {
            return Ok(None);
        }
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
        conversation_gen: u64,
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
                    return Err(FetchError::NotFound {
                        message: format!(
                            "{name} is no longer on the server: it was deleted from the server, its \
                             upload was cancelled, or it expired (the server keeps attachments \
                             temporarily)"
                        ),
                        conversation_gen: Some(conversation_gen),
                    });
                }
                Err(e) => return Err(FetchError::Other(describe(&e))),
            }
        }
    }

    /// Keep chunk `index` of the attachment `id`, in the chat with `peer`, unless its upload was
    /// cancelled or the chat deleted/recreated meanwhile. Returns `Ok(true)` if kept.
    pub(super) async fn keep_chunk_for_gen(
        &self,
        peer: &PublicKey,
        id: &[u8],
        index: u32,
        chunk: &[u8],
        expected_gen: Option<u64>,
    ) -> Result<bool, String> {
        let guard = self.lock_inner().await;
        let inner = guard.as_ref().ok_or("locked")?;
        if !self.may_keep_for_gen(inner, peer, id, expected_gen) {
            return Ok(false);
        }
        inner
            .vault
            .put_chunk(peer, id, index, chunk)
            .await
            .map_err(|e| describe(&e))?;
        Ok(true)
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
                let message = contact.message_at(index, entry, now);
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
                        let gone = gone
                            || contact.is_attachment_deleted(&remote.pointer.id)
                            || expired(&remote.pointer, now);
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
