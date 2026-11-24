//! Attachment uploads, downloads and local file storage.

use super::contact::keep_last;
use super::{
    Engine, HISTORY_SHOWN, Inner, MAX_FILE_SIZE, NOT_SIGNED_IN_HERE, POLL_CHUNK_MAX,
    POLL_CHUNK_MIN, RETRY_MAX, RETRY_MIN, STALLED, WAITS_SIGN_IN, attachment_key_hash, origin,
    records, same_server,
};
use crate::content::{AttachmentPointer, Content, Kind};
use crate::preview;
use crate::preview::Sort;
use crate::state::{Attachment, Body, Delivery, FileView, Link, Opening, UploadState, UploadView};
use crate::transport::{Connect, Fetch, Progress};
use crate::util::{describe, js_error, size_u64, sleep};
use crate::vault::{HistoryEntry, OutgoingRecord, PendingUpload, outbox_key};
use leptos::prelude::*;
use leptos::task::spawn_local;
use session::attachment::{CHUNK_SIZE, Upload};
use session::{ErrorKind, PublicKey, attachment};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

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

impl Engine {
    /// Send `peer` an attachment of `file`, then upload it: the peer can download it meanwhile,
    /// and what was sent after it goes without waiting for the upload. Its chunks are kept here
    /// too, so it opens without the server. Each chunk is read as its turn comes, and the upload
    /// is kept in the vault as it goes, so that it can go on after the page goes.
    pub(super) async fn send_attachment(
        self: &Rc<Self>,
        peer: PublicKey,
        file: web_sys::File,
    ) -> Result<(), String> {
        let size = file.size() as u64;
        let (started, signs_in_here, server) = {
            let mut guard = self.inner.lock().await;
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
        let upload = match started {
            Ok(upload) => upload,
            // The server keeps attachments only for those signed in to it: its message takes its
            // place in the chat, and waits, with what is sent after it, until this browser is.
            Err(e) if e.kind() == ErrorKind::SignInRequired && signs_in_here => {
                self.wait_for_sign_in(peer, file).await?;
                self.ask_sign_in();
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
            mime: file.type_(),
            size,
            uploaded: 0,
            encrypted: 0,
            prefix_hash: Sha256::digest([]).to_vec(),
            announced: false,
            history_index: 0,
        };
        if let Err(e) = self.save_upload(&peer, &pending).await {
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Err(e);
        }
        self.files.borrow_mut().insert(
            (peer, *upload.id(), attachment_key_hash(upload.key())),
            file.clone(),
        );
        let pending = match self.announce(&peer, pending).await {
            Ok(Some(pending)) => pending,
            Ok(None) => return Ok(()),
            Err(AnnounceError::NotSent(e)) => {
                self.cancelled.borrow_mut().insert(*upload.id());
                self.remove_attachment_caches(&peer, upload.id());
                {
                    let guard = self.inner.lock().await;
                    if let Some(inner) = guard.as_ref() {
                        let _ = inner.vault.forget_upload(&peer, upload.id()).await;
                    }
                }
                let _ = upload.cancel(&Fetch::client(&server)).await;
                return Err(e);
            }
            Err(AnnounceError::SaveAfterSend { error, pending }) => {
                let keep = {
                    let guard = self.inner.lock().await;
                    guard
                        .as_ref()
                        .is_some_and(|inner| self.may_keep(inner, &peer, upload.id()))
                };
                if keep {
                    self.show_upload(&peer, &pending, UploadState::Paused(error.clone()));
                } else {
                    self.cancelled.borrow_mut().insert(*upload.id());
                    self.remove_attachment_caches(&peer, upload.id());
                    let _ = upload.cancel(&Fetch::client(&server)).await;
                }
                return Err(error);
            }
        };
        // A new upload, which nothing else runs.
        self.running.borrow_mut().insert(*upload.id());
        self.show_upload(&peer, &pending, UploadState::Running);
        let engine = self.clone();
        spawn_local(async move {
            if let Err(e) = engine.run_upload(peer, pending, file, Sha256::new()).await {
                engine.ui.notify(e);
            }
        });
        Ok(())
    }

    /// Keep `file`, to `peer`, until this browser signs in to the server, which takes no
    /// attachment before: its message takes its place in the chat at once, waiting, and what is
    /// sent after it waits for it, see `flush`. Its upload, kept under an ID of this client's,
    /// starts once signed in, see [`start_waiting`](Self::start_waiting); after the page goes,
    /// once the file is chosen again.
    async fn wait_for_sign_in(&self, peer: PublicKey, file: web_sys::File) -> Result<(), String> {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|e| e.to_string())?;
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        let contact = inner.contact(&peer).ok_or("no such chat")?;
        let waiting = PendingUpload {
            id: id.to_vec(),
            name: file.name(),
            mime: file.type_(),
            size: file.size() as u64,
            announced: true,
            history_index: contact.state.history_len,
            token: Vec::new(),
            key: Vec::new(),
            uploaded: 0,
            encrypted: 0,
            prefix_hash: Vec::new(),
            expires: 0,
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
        self.show_new(inner, &peer, vec![view]);
        self.ui.contacts.set(inner.views());
        drop(guard);
        self.files
            .borrow_mut()
            .insert((peer, id, attachment_key_hash(&[])), file);
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
        let waiting = {
            let guard = self.inner.lock().await;
            let Some(inner) = guard.as_ref() else {
                return;
            };
            match inner.vault.uploads(None).await {
                Ok(uploads) => uploads,
                Err(e) => return self.ui.notify(describe(&e)),
            }
        };
        for (peer, pending) in waiting.into_iter().filter(|(_, p)| !p.started()) {
            let Ok(id) = <[u8; 16]>::try_from(pending.id.as_slice()) else {
                continue;
            };
            if self.cancelled.borrow().contains(&id) || self.running.borrow().contains(&id) {
                continue;
            }
            let key = (peer, id, attachment_key_hash(&pending.key));
            let Some(file) = self.files.borrow().get(&key).cloned() else {
                // Re-check under the lock so an upload already promoted by a concurrent
                // `resume_upload` or dropped by `SealOutcome::Failed` is never resurrected.
                let still_waiting = {
                    let guard = self.inner.lock().await;
                    let Some(inner) = guard.as_ref() else {
                        return;
                    };
                    if self.cancelled.borrow().contains(&id) || self.running.borrow().contains(&id)
                    {
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
                if still_waiting {
                    self.show_upload(
                        &peer,
                        &pending,
                        UploadState::Paused("choose the file again to upload".to_string()),
                    );
                }
                continue;
            };
            if !self.running.borrow_mut().insert(id) {
                continue;
            }
            let result = self.start_waiting(peer, id, file).await;
            self.running.borrow_mut().remove(&id);
            if let Err(e) = result {
                self.ui.notify(e);
            }
        }
    }

    /// Start the upload `waiting`, to `peer`, of `file`, which waited for this browser to sign
    /// in: its message, which kept its place in the chat, gets the attachment and goes, with
    /// what waited for it, and the upload runs. Refused again, it waits again.
    async fn start_waiting(
        self: &Rc<Self>,
        peer: PublicKey,
        waiting: [u8; 16],
        file: web_sys::File,
    ) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        if self.cancelled.borrow().contains(&waiting) {
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
        if file.size() as u64 != kept.size {
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
        if self.cancelled.borrow().contains(&waiting) {
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
                if self.cancelled.borrow().contains(&waiting) {
                    return Ok(());
                }
                self.files
                    .borrow_mut()
                    .insert((peer, waiting, attachment_key_hash(&kept.key)), file);
                self.show_upload(&peer, &kept, UploadState::Paused(WAITS_SIGN_IN.to_string()));
                self.ask_sign_in();
                return Ok(());
            }
            Err(e) => {
                if self.cancelled.borrow().contains(&waiting) {
                    return Ok(());
                }
                // Report attachment 404/Unimplemented locally without tripping global update_required.
                return Err(describe(&e));
            }
        };
        let server = inner.server.clone();
        // Cancelled meanwhile: the server forgets it too, and cancelling fails its message.
        if self.cancelled.borrow().contains(&waiting) {
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
            announced: kept.announced,
        };
        // Kept under the server's ID first: if the message is not saved after, the upload is
        // there to cancel, rather than a message with nothing to download.
        if let Err(e) = inner.vault.save_upload(&peer, &pending).await {
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Err(describe(&e));
        }
        let content = Kind::Attachment(pointer);
        let record = OutgoingRecord {
            message: None,
            content: content.to_bytes(),
            delivery_hash: vec![],
        };
        entry.content = Some(Content {
            kind: Some(content),
            ..entry.content.unwrap_or_default()
        });
        let Some(contact) = inner.contact(&peer) else {
            let _ = inner.vault.forget_upload(&peer, upload.id()).await;
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Err("no such chat".into());
        };
        let snapshot = contact.snapshot();
        for outgoing in &mut contact.state.outbox {
            if outgoing.history_index == kept.history_index {
                outgoing.awaits_upload = false;
            }
        }
        let mut changed = [(kept.history_index, entry)];
        let saved = inner
            .save_with(
                &records(&peer, &changed),
                &[(outbox_key(&peer, kept.history_index), Some(record))],
            )
            .await;
        if let Err(e) = saved {
            inner.roll_back(&peer, snapshot)?;
            let _ = inner.vault.forget_upload(&peer, upload.id()).await;
            let _ = upload.cancel(&Fetch::client(&server)).await;
            return Err(describe(&e));
        }
        // Its message has the attachment now: a record left behind is forgotten when found.
        if let Err(e) = inner.vault.forget_upload(&peer, &waiting).await {
            self.ui.log(format!(
                "could not forget the wait of {}: {}",
                pending.name,
                describe(&e)
            ));
        }
        // Cancelled while it started, which found nothing left to cancel: it goes no further,
        // and its message reverts to an un-uploaded failed attachment without publishing the
        // cancelled pointer ID to the UI.
        if self.cancelled.borrow().contains(&waiting) {
            self.cancelled.borrow_mut().insert(*upload.id());
            self.remove_attachment_caches(&peer, &waiting);
            self.remove_attachment_caches(&peer, upload.id());
            let _ = upload.cancel(&Fetch::client(&inner.server)).await;
            let _ = inner.vault.forget_upload(&peer, upload.id()).await;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            let fail_snapshot = contact.snapshot();
            contact
                .state
                .outbox
                .retain(|outgoing| outgoing.history_index != kept.history_index);
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
            if let Err(e) = inner
                .save_with(
                    &records(&peer, &changed),
                    &[(outbox_key(&peer, kept.history_index), None)],
                )
                .await
            {
                inner.roll_back(&peer, fail_snapshot)?;
                return Err(describe(&e));
            }
            self.release(&peer, kept.history_index);
            self.show_changes(inner, &peer, &changed);
            drop(guard);
            if let Err(e) = self.flush(&peer).await {
                self.ui.link.set(Link::Offline(e));
            }
            return Ok(());
        }
        self.show_changes(inner, &peer, &changed);
        drop(guard);
        // Under the server's ID and key hash from now on.
        self.remove_attachment_caches(&peer, &waiting);
        self.files.borrow_mut().insert(
            (peer, *upload.id(), attachment_key_hash(upload.key())),
            file.clone(),
        );
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != waiting));
        self.running.borrow_mut().remove(&waiting);
        self.running.borrow_mut().insert(*upload.id());
        self.show_upload(&peer, &pending, UploadState::Running);
        self.release(&peer, kept.history_index);
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
        // If `flush` permanently failed or `cancel_held`/`cancel_upload` cancelled the upload
        // while announcing, stop without uploading chunks to R2.
        let failed_or_cancelled = self.cancelled.borrow().contains(upload.id()) || {
            let guard = self.inner.lock().await;
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
            self.running.borrow_mut().remove(upload.id());
            self.wake();
            return Ok(());
        }
        self.wake();
        let engine = self.clone();
        spawn_local(async move {
            if let Err(e) = engine.run_upload(peer, pending, file, Sha256::new()).await {
                engine.ui.notify(e);
            }
        });
        Ok(())
    }

    /// Send the attachment of `pending` to `peer`, unless sent already, and keep that it was.
    /// Returns `Ok(None)` if the announcement permanently failed or was cancelled during `flush`.
    async fn announce(
        &self,
        peer: &PublicKey,
        mut pending: PendingUpload,
    ) -> Result<Option<PendingUpload>, AnnounceError> {
        if pending.announced {
            return Ok(Some(pending));
        }
        let id_arr = <[u8; 16]>::try_from(pending.id.as_slice()).ok();
        // Hold one lock across scanning history for an already-persisted announcement, checking
        // cancellation/chat deletion, and adding a new outgoing message so a queued `cancel_upload`
        // or `delete(peer)` cannot slip in before `inner.add` and send a deleted attachment.
        let (index, added_new) = {
            let mut guard = self.inner.lock().await;
            let Some(inner) = guard.as_mut() else {
                return Err(AnnounceError::NotSent("locked".into()));
            };
            let mut end = inner
                .contacts
                .iter()
                .find(|contact| contact.peer == *peer)
                .map_or(0, |contact| contact.state.history_len);
            let mut found = None;
            while end > 0 && found.is_none() {
                let page = inner
                    .vault
                    .history(peer, end, HISTORY_SHOWN)
                    .await
                    .map_err(|e| AnnounceError::NotSent(describe(&e)))?;
                found = page.into_iter().rev().find_map(|(idx, entry)| {
                    (entry.outgoing
                        && matches!(
                            entry.content.as_ref().and_then(|c| c.kind.as_ref()),
                            Some(Kind::Attachment(pointer)) if pointer.id == pending.id
                        ))
                    .then_some(idx)
                });
                end = end.saturating_sub(HISTORY_SHOWN);
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
                    let index = view.index;
                    self.show_new(inner, peer, vec![view]);
                    self.ui.contacts.set(inner.views());
                    (index, true)
                }
            }
        };
        if added_new {
            // Saved, so it goes in a later sync if not now.
            if let Err(e) = self.flush(peer).await {
                self.ui.link.set(Link::Offline(e));
            }
            self.wake();
        }
        // Hold one lock across checking delivery failure, concurrent cancellation/chat deletion,
        // and persisting `announced = true` so a concurrent cancel cannot race into a spurious
        // `"the upload of ... was cancelled"` error toast or mark an offline cancel gone early.
        pending.announced = true;
        pending.history_index = index;
        let mut guard = self.inner.lock().await;
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
        if entry_failed {
            self.cancel_uploads_for_failed(inner, peer, &[index]).await;
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
        let guard = self.inner.lock().await;
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
        self.files
            .borrow_mut()
            .retain(|(p, i, _), _| !(p == peer && i == id));
        self.decrypted
            .borrow_mut()
            .retain(|((p, i, _, _), _)| !(p == peer && i == id));
    }

    /// Whether the file of the upload `id` for `peer` is still here, so that it can go on without
    /// the file chosen again.
    pub fn has_file(&self, peer: &PublicKey, id: &[u8; 16]) -> bool {
        self.files
            .borrow()
            .keys()
            .any(|(p, i, _)| p == peer && i == id)
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
        // Guard the upload ID in `self.running` up front so double-clicking Resume on either a
        // sign-in-held (`!started()`) upload or a started upload cannot race `start_waiting` and
        // surface a spurious `"that upload is gone"` error.
        if self.cancelled.borrow().contains(&id) || !self.running.borrow_mut().insert(id) {
            return Ok(());
        }
        // Look up the pending upload once under the lock, exiting quietly if it was cancelled or
        // forgotten concurrently (e.g. by `cancel_upload`, `SealOutcome::Failed`, or `delete`).
        let pending = {
            let guard = self.inner.lock().await;
            let Some(inner) = guard.as_ref() else {
                self.running.borrow_mut().remove(&id);
                return Err("locked".into());
            };
            match inner.vault.upload(&peer, &id).await {
                Ok(Some(pending)) => {
                    if self.cancelled.borrow().contains(&id) {
                        self.running.borrow_mut().remove(&id);
                        return Ok(());
                    }
                    pending
                }
                Ok(None) => {
                    self.running.borrow_mut().remove(&id);
                    if self.cancelled.borrow().contains(&id) {
                        return Ok(());
                    }
                    return Err("that upload is gone".into());
                }
                Err(e) => {
                    self.running.borrow_mut().remove(&id);
                    return Err(describe(&e));
                }
            }
        };
        // One that waited for a sign-in starts, its message in its place.
        if !pending.started() {
            let key = (peer, id, attachment_key_hash(&[]));
            let file = match file.or_else(|| self.files.borrow().get(&key).cloned()) {
                Some(file) => file,
                None => {
                    self.running.borrow_mut().remove(&id);
                    return Err("choose the file again".into());
                }
            };
            let result = self.start_waiting(peer, id, file).await;
            self.running.borrow_mut().remove(&id);
            return result;
        }
        let resumed = async {
            let cache_key = (peer, id, attachment_key_hash(&pending.key));
            let file = file
                .or_else(|| self.files.borrow().get(&cache_key).cloned())
                .ok_or("choose the file again")?;
            let hasher = match self.check(&peer, &pending, &file).await {
                Ok(hasher) => hasher,
                Err(e) => {
                    if !self.cancelled.borrow().contains(&id) {
                        self.show_upload(&peer, &pending, UploadState::Paused(e.clone()));
                    }
                    return Err(e);
                }
            };
            // Cancelled while the file was checked: it is not sent.
            if self.cancelled.borrow().contains(&id) {
                return Ok(None);
            }
            self.files.borrow_mut().insert(cache_key, file.clone());
            let before_announce = pending.clone();
            let pending = match self.announce(&peer, pending).await {
                Ok(Some(pending)) => pending,
                Ok(None) => return Ok(None),
                Err(err) => {
                    let msg = err.into_message();
                    if !self.cancelled.borrow().contains(&id) {
                        self.show_upload(&peer, &before_announce, UploadState::Paused(msg.clone()));
                    }
                    return Err(msg);
                }
            };
            Ok::<_, String>(Some((pending, file, hasher)))
        }
        .await;
        match resumed {
            Ok(Some((pending, file, hasher))) => self.run_upload(peer, pending, file, hasher).await,
            Ok(None) => {
                self.running.borrow_mut().remove(&id);
                Ok(())
            }
            Err(e) => {
                self.running.borrow_mut().remove(&id);
                Err(e)
            }
        }
    }

    /// Stop the upload `id`, in the chat with `peer`, and forget it. The server deletes what it
    /// has, so the peer finds the attachment gone; if it cannot be reached, what it has expires.
    pub async fn cancel_upload(&self, peer: PublicKey, id: [u8; 16]) -> Result<(), String> {
        // For good, running or not: what is on its way stops, and keeps nothing of it again.
        self.cancelled.borrow_mut().insert(id);
        self.remove_attachment_caches(&peer, &id);
        self.ui
            .uploads
            .update(|uploads| uploads.retain(|upload| upload.id != id));
        let mut guard = self.inner.lock().await;
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
        let deleted_on_server = if let Some(pending) = &pending {
            match upload_of(pending)?
                .cancel(&Fetch::client(&inner.server))
                .await
            {
                Ok(()) => true,
                Err(e) if e.kind() == ErrorKind::NotFound => true,
                Err(e) => {
                    self.ui.log(format!(
                        "the server keeps what it has of {} until it expires: {}",
                        pending.name,
                        describe(&e)
                    ));
                    false
                }
            }
        } else {
            false
        };
        let started = pending.as_ref().is_some_and(PendingUpload::started);
        let announced = pending
            .as_ref()
            .filter(|pending| pending.announced)
            .map(|pending| pending.history_index);
        inner
            .vault
            .forget_upload(&peer, &id)
            .await
            .map_err(|e| describe(&e))?;
        if started && deleted_on_server {
            let _ = self.note_gone_inner(inner, &peer, announced, &id).await;
        }
        Ok(())
    }

    /// Cancel the message at `index`, to `peer`, held until this browser signs in to the server:
    /// it fails, and what waited for it goes, unless it too needs the sign-in. One whose
    /// attachment's upload has not started goes with its upload.
    pub async fn cancel_held(&self, peer: PublicKey, index: u64) -> Result<(), String> {
        let waiting = {
            let guard = self.inner.lock().await;
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
        if let Some(id) = waiting {
            return self.cancel_upload(peer, id).await;
        }
        {
            let mut guard = self.inner.lock().await;
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
            self.cancel_uploads_for_failed(inner, &peer, &[index]).await;
        }
        self.waits_sign_in.borrow_mut().remove(&peer);
        if let Err(e) = self.flush(&peer).await {
            self.ui.link.set(Link::Offline(e));
        }
        self.wake();
        Ok(())
    }

    /// Cancel and forget any unstarted or started uploads associated with permanently failed or
    /// cancelled history entries `failed_indices`, preventing orphaned R2 uploads and ghost rows.
    pub(super) async fn cancel_uploads_for_failed(
        &self,
        inner: &mut Inner,
        peer: &PublicKey,
        failed_indices: &[u64],
    ) {
        if failed_indices.is_empty() {
            return;
        }
        struct FailedAttachment {
            index: u64,
            key: Option<Zeroizing<[u8; attachment::KEY_LENGTH]>>,
            gone: bool,
        }
        let mut by_id: std::collections::HashMap<[u8; 16], FailedAttachment> =
            std::collections::HashMap::new();
        for &idx in failed_indices {
            if let Ok(Some(entry)) = inner.vault.entry(peer, idx).await
                && let Some(Kind::Attachment(pointer)) =
                    entry.content.as_ref().and_then(|c| c.kind.as_ref())
                && let Ok(id) = <[u8; 16]>::try_from(pointer.id.as_slice())
            {
                let key = <[u8; attachment::KEY_LENGTH]>::try_from(pointer.key.as_slice())
                    .ok()
                    .map(Zeroizing::new);
                by_id.insert(
                    id,
                    FailedAttachment {
                        index: idx,
                        key,
                        gone: entry.gone,
                    },
                );
            }
        }
        let uploads = inner.vault.uploads(Some(peer)).await.unwrap_or_default();
        let mut handled_ids = std::collections::HashSet::new();
        for (_, pending) in uploads {
            let Ok(id) = <[u8; 16]>::try_from(pending.id.as_slice()) else {
                continue;
            };
            let matched_index = by_id.get(&id).map(|item| item.index).or_else(|| {
                (pending.announced || !pending.started())
                    .then_some(pending.history_index)
                    .filter(|idx| failed_indices.contains(idx))
            });
            if matched_index.is_none() && !by_id.contains_key(&id) {
                continue;
            }
            self.cancelled.borrow_mut().insert(id);
            self.remove_attachment_caches(peer, &id);
            self.ui
                .uploads
                .update(|uploads| uploads.retain(|item| item.id != id));
            let mut deleted_on_server = false;
            if pending.started() {
                if let Ok(upload) = upload_of(&pending) {
                    handled_ids.insert(id);
                    match upload.cancel(&Fetch::client(&inner.server)).await {
                        Ok(()) => deleted_on_server = true,
                        Err(e) if e.kind() == ErrorKind::NotFound => deleted_on_server = true,
                        Err(e) => {
                            self.ui.log(format!(
                                "the server keeps what it has of {} until it expires: {}",
                                pending.name,
                                describe(&e)
                            ));
                        }
                    }
                }
                // If `upload_of(&pending)` fails, leave `id` out of `handled_ids` so the `by_id`
                // pass below can still attempt `attachment::delete` via `pointer.key`.
            } else {
                handled_ids.insert(id);
            }
            let _ = inner.vault.forget_upload(peer, &id).await;
            if deleted_on_server {
                let _ = self.note_gone_inner(inner, peer, matched_index, &id).await;
            }
        }
        for (id, item) in by_id {
            if handled_ids.contains(&id) {
                continue;
            }
            self.cancelled.borrow_mut().insert(id);
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
            // object via its delete token, and only mark `gone` once confirmed deleted/not found
            // so transient offline failures stay retryable from the Files dialog.
            match attachment::delete(&Fetch::client(&inner.server), &id, &key).await {
                Ok(()) => {
                    let _ = self
                        .note_gone_inner(inner, peer, Some(item.index), &id)
                        .await;
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    let _ = self
                        .note_gone_inner(inner, peer, Some(item.index), &id)
                        .await;
                }
                Err(e) => {
                    self.ui.log(format!(
                        "could not delete cancelled attachment from server: {}",
                        describe(&e)
                    ));
                }
            }
        }
    }

    /// Show the message at `index`, to `peer`, as held until this browser signs in.
    pub(super) fn hold(&self, peer: &PublicKey, index: u64) {
        self.ui.held.update(|held| {
            held.insert((*peer, index));
        });
    }

    /// Show the message at `index`, to `peer`, as no longer held.
    pub(super) fn release(&self, peer: &PublicKey, index: u64) {
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

    /// The hash of `file` as far as `pending` may have encrypted it, once it is what it was then.
    pub(super) async fn check(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        file: &web_sys::File,
    ) -> Result<Sha256, String> {
        let other = || format!("that is not {}, or it changed", pending.name);
        if file.size() as u64 != pending.size {
            return Err(other());
        }
        self.show_upload(peer, pending, UploadState::Checking);
        let mut hasher = Sha256::new();
        for index in 0..pending.encrypted {
            hasher.update(read_chunk(file, index, pending.size).await?);
        }
        if hasher.clone().finalize().as_slice() != pending.prefix_hash {
            return Err(other());
        }
        Ok(hasher)
    }

    /// Upload the chunks of `pending` from where it is: `hasher` has hashed its first
    /// `encrypted` chunks. While it goes, the upload shows in its chat, and if
    /// it stops, it shows paused, with why. The caller has marked it running, which this ends.
    async fn run_upload(
        &self,
        peer: PublicKey,
        mut pending: PendingUpload,
        file: web_sys::File,
        hasher: Sha256,
    ) -> Result<(), String> {
        let id: [u8; 16] = pending.id.as_slice().try_into().unwrap_or_default();
        let uploaded = match upload_of(&pending) {
            Ok(upload) => {
                self.upload_chunks(&peer, &mut pending, &upload, &file, hasher)
                    .await
            }
            Err(e) => Err(e),
        };
        self.running.borrow_mut().remove(&id);
        // Cancelled, it stays so: what cancelled it forgot it.
        if self.cancelled.borrow().contains(&id) {
            return Ok(());
        }
        match uploaded {
            Ok(true) => {}
            // Deleted from the server, e.g. by the peer, who did not want it: the rest need not
            // go up.
            Ok(false) => {
                self.drop_upload(&peer, id).await?;
                if pending.announced {
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
                let gone = self.cancelled.borrow().contains(&id) || {
                    let guard = self.inner.lock().await;
                    guard
                        .as_ref()
                        .is_some_and(|inner| !self.may_keep(inner, &peer, &id))
                };
                if gone {
                    self.remove_attachment_caches(&peer, &id);
                    self.ui
                        .uploads
                        .update(|uploads| uploads.retain(|upload| upload.id != id));
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
        let guard = self.inner.lock().await;
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
        let guard = self.inner.lock().await;
        let inner = guard.as_ref().ok_or("locked")?;
        let kept = inner
            .vault
            .upload(peer, &id)
            .await
            .map_err(|e| describe(&e))?
            .is_some();
        if !kept && !self.running.borrow().contains(&id) {
            return Ok(());
        }
        self.cancelled.borrow_mut().insert(id);
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
        let not_there = || format!("{} is not on the server", pointer.name);
        let id: [u8; 16] = pointer.id.as_slice().try_into().map_err(|_| not_there())?;
        let key = Zeroizing::new(pointer.key.as_slice().try_into().map_err(|_| not_there())?);
        let server = {
            let guard = self.inner.lock().await;
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
        let mut guard = self.inner.lock().await;
        let inner = guard.as_mut().ok_or("locked")?;
        self.note_gone_inner(inner, peer, hint_index, id).await
    }

    async fn note_gone_inner(
        &self,
        inner: &mut Inner,
        peer: &PublicKey,
        hint_index: Option<u64>,
        id: &[u8; 16],
    ) -> Result<(), String> {
        let matches_id = |entry: &HistoryEntry| {
            matches!(
                entry.content.as_ref().and_then(|content| content.kind.as_ref()),
                Some(Kind::Attachment(pointer)) if pointer.id == id
            )
        };
        let mut found: Option<(u64, HistoryEntry)> = None;
        if let Some(index) = hint_index
            && let Some(entry) = inner
                .vault
                .entry(peer, index)
                .await
                .map_err(|e| describe(&e))?
                .filter(matches_id)
        {
            found = Some((index, entry));
        }
        if found.is_none() {
            let mut end = inner
                .contacts
                .iter()
                .find(|contact| contact.peer == *peer)
                .map_or(0, |contact| contact.state.history_len);
            while end > 0 && found.is_none() {
                let page = inner
                    .vault
                    .history(peer, end, HISTORY_SHOWN)
                    .await
                    .map_err(|e| describe(&e))?;
                found = page.into_iter().rev().find(|(_, entry)| matches_id(entry));
                end = end.saturating_sub(HISTORY_SHOWN);
            }
        }
        let Some((index, mut entry)) = found else {
            return Ok(());
        };
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

    /// Upload the chunks of `pending` from `uploaded` on, reading each from `file` in its turn,
    /// unless the upload is cancelled. Returns whether the server still has the attachment: one
    /// deleted meanwhile, e.g. by the peer, is not found.
    async fn upload_chunks(
        &self,
        peer: &PublicKey,
        pending: &mut PendingUpload,
        upload: &Upload,
        file: &web_sys::File,
        mut hasher: Sha256,
    ) -> Result<bool, String> {
        let server = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or("locked")?.server.clone()
        };
        // Each chunk shows how far it got as it goes: the bytes before it, and its share of what
        // its request sent.
        let before = Rc::new(Cell::new(0));
        let progress: Progress = {
            let (ui, before, id, size) = (self.ui, before.clone(), *upload.id(), pending.size);
            Rc::new(move |sent, total| {
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
            if self.cancelled.borrow().contains(upload.id()) {
                return Ok(true);
            }
            before.set((u64::from(index) * CHUNK_SIZE as u64).min(pending.size));
            self.show_upload(peer, pending, UploadState::Running);
            let plaintext = read_chunk(file, index, pending.size).await?;
            // Kept before the chunk is encrypted: from then on, the file must not change there.
            if index >= pending.encrypted {
                hasher.update(&plaintext);
                pending.encrypted = index + 1;
                pending.prefix_hash = hasher.clone().finalize().to_vec();
            }
            pending.uploaded = index;
            self.save_upload(peer, pending).await?;
            let chunk = upload
                .try_encrypt(index, &plaintext)
                .map_err(|e| describe(&e))?;
            if !self
                .put_chunk(peer, pending, &attachments, upload, index, &chunk)
                .await?
            {
                return Ok(false);
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
        let mut wait = RETRY_MIN;
        loop {
            match upload.put(attachments, index, chunk).await {
                Ok(()) => return Ok(true),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
                Err(e) if e.kind() == ErrorKind::Server => {
                    if self.cancelled.borrow().contains(upload.id()) {
                        return Ok(true);
                    }
                    self.show_upload(peer, pending, UploadState::Retrying);
                    sleep(wait).await;
                    wait = (wait * 2).min(RETRY_MAX);
                    if self.cancelled.borrow().contains(upload.id()) {
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
        let guard = self.inner.lock().await;
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
    pub(super) fn may_keep(&self, inner: &Inner, peer: &PublicKey, id: &[u8]) -> bool {
        let cancelled =
            <[u8; 16]>::try_from(id).is_ok_and(|id| self.cancelled.borrow().contains(&id));
        !cancelled && inner.contacts.iter().any(|contact| contact.peer == *peer)
    }

    /// Show the upload `pending`, to `peer`, as in `state`.
    pub(super) fn show_upload(
        &self,
        peer: &PublicKey,
        pending: &PendingUpload,
        state: UploadState,
    ) {
        let id: [u8; 16] = pending.id.as_slice().try_into().unwrap_or_default();
        if self.cancelled.borrow().contains(&id) {
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
            id,
            name: pointer.name.clone(),
            size: pointer.size,
            done: 0,
            waiting: false,
        }));
        let fetched = self
            .fetch_attachment(peer, index, &id, pointer, Waiter::Viewer(token))
            .await;
        if let Err(FetchError::NotFound(_)) = &fetched {
            let _ = self.note_gone_by_id(&peer, Some(index), &id).await;
        }
        let opened = self
            .told_downloaded(peer, clock, fetched.map_err(FetchError::into_message))
            .await;
        // Unless the viewer closed, navigated away, or started another request (even for the same
        // attachment ID) meanwhile.
        if !self.opening(token, &id) {
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
        let Ok(id) = <[u8; 16]>::try_from(pointer.id.as_slice()) else {
            return Err("the attachment is malformed".to_string());
        };
        let fetched = self
            .fetch_attachment(peer, index, &id, pointer, Waiter::Chat(shows))
            .await;
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
        let Some((attachment, from_server)) = fetched? else {
            return Ok(None);
        };
        if from_server
            && clock > 0
            && let Err(e) = self.downloaded(peer, clock).await
        {
            self.ui.link.set(Link::Offline(e));
        }
        Ok(Some(attachment))
    }

    /// Tell `peer` that its attachment, sent in its message at `clock`, is downloaded.
    pub(super) async fn downloaded(&self, peer: PublicKey, clock: u64) -> Result<(), String> {
        {
            let mut guard = self.inner.lock().await;
            let inner = guard.as_mut().ok_or("locked")?;
            let contact = inner.contact(&peer).ok_or("no such chat")?;
            let events = contact.state.events.get_or_insert_default();
            events.downloaded.push(clock);
            keep_last(&mut events.downloaded);
            inner.save_state().await.map_err(|e| describe(&e))?;
        }
        self.flush(&peer).await.map(drop)
    }

    /// Whether the viewer still waits for the attachment `id` of preview request `token`.
    fn opening(&self, token: u64, id: &[u8; 16]) -> bool {
        self.ui.opening.with_untracked(|opening| {
            opening
                .as_ref()
                .is_some_and(|opening| opening.token == token && opening.id == *id)
        })
    }

    /// Note how far opening the attachment `id` of preview request `token` got.
    pub(super) fn opened(&self, token: u64, id: &[u8; 16], done: u64, waiting: bool) {
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
        pointer: AttachmentPointer,
        waiter: Waiter<'_>,
    ) -> Result<Option<(Attachment, bool)>, FetchError> {
        // The sender's own, while on the page that chose it: keyed by `(peer, id, key_hash)` so
        // another peer or mismatched key can never read a cached plaintext file (M-13).
        let key_hash = attachment_key_hash(&pointer.key);
        let file = self.files.borrow().get(&(peer, *id, key_hash)).cloned();
        if let Some(file) = file {
            let buffer = JsFuture::from(file.array_buffer()).await.map_err(|e| {
                FetchError::Other(format!("Cannot read {}: {}", pointer.name, js_error(e)))
            })?;
            let attachment = Attachment {
                name: pointer.name,
                mime: pointer.mime,
                data: Arc::new(js_sys::Uint8Array::new(&buffer).to_vec()),
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
            name: pointer.name,
            mime: pointer.mime,
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
        let key = Zeroizing::new(
            <[u8; attachment::KEY_LENGTH]>::try_from(pointer.key.as_slice())
                .map_err(|_| malformed())?,
        );
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
        let guard = self.inner.lock().await;
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
        let (chunk, kept) = match self
            .kept_chunk(&fetching.peer, &fetching.id, index)
            .await
            .map_err(FetchError::Other)?
        {
            Some(chunk) => (chunk, true),
            None if fetching
                .unfinished
                .is_some_and(|uploaded| index >= uploaded) =>
            {
                return Err(FetchError::Other(format!(
                    "{} is not all uploaded: choose the file again to go on",
                    fetching.name
                )));
            }
            None => match self
                .await_chunk(
                    &fetching.attachments,
                    &fetching.name,
                    &fetching.id,
                    index,
                    waiter,
                )
                .await?
            {
                Some(chunk) => (chunk, false),
                None => return Ok(None),
            },
        };
        let last = index + 1 == fetching.chunks;
        let plaintext = attachment::decrypt_chunk(&fetching.key, index, last, &chunk)
            .map_err(|_| FetchError::Other(format!("{} does not decrypt", fetching.name)))?;
        // Kept only once it decrypts, so that a chunk that does not is fetched again next time
        // rather than kept for good.
        if !kept {
            self.keep_chunk(&fetching.peer, &fetching.id, index, &chunk)
                .await
                .map_err(FetchError::Other)?;
        }
        Ok(Some((plaintext, !kept)))
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
        let guard = self.inner.lock().await;
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
        let guard = self.inner.lock().await;
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
        let mut files = vec![];
        // The server's time, by which the attachments it deleted already are not offered.
        let now = {
            let guard = self.inner.lock().await;
            guard.as_ref().ok_or("locked")?.client.clock().now()
        };
        let mut end = u64::MAX;
        loop {
            let guard = self.inner.lock().await;
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
    file: &web_sys::File,
    index: u32,
    size: u64,
) -> Result<Vec<u8>, String> {
    let start = u64::from(index) * CHUNK_SIZE as u64;
    read(file, start, (start + CHUNK_SIZE as u64).min(size)).await
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

/// The upload of `pending`, to go on with, refusing re-encryption below `pending.uploaded`.
pub(super) fn upload_of(pending: &PendingUpload) -> Result<Upload, String> {
    let corrupt = || format!("the upload of {} is corrupt", pending.name);
    let chunks = u32::try_from(attachment::chunk_count(pending.size)).map_err(|_| corrupt())?;
    let token: [u8; 16] = pending.token.as_slice().try_into().map_err(|_| corrupt())?;
    Ok(Upload::resume_from(
        pending.id.as_slice().try_into().map_err(|_| corrupt())?,
        Zeroizing::new(token),
        Zeroizing::new(pending.key.as_slice().try_into().map_err(|_| corrupt())?),
        chunks,
        pending.uploaded,
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
