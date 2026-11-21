//! Range requests and decrypted chunk caching for streaming media.

use super::attachments::{FetchError, Fetching, Waiter, read_chunk};
use super::{CHUNKS_DECRYPTED_KEPT, ChunkOf, Engine};
use crate::content::AttachmentPointer;
use crate::glue::MediaRequest;
use crate::state::Link;
use crate::util::hex;
use crate::{glue, preview};
use futures::channel::oneshot;
use leptos::prelude::*;
use session::PublicKey;
use session::attachment::CHUNK_SIZE;
use std::collections::hash_map;
use std::rc::Rc;

/// An attachment playing as it is fetched, through the service worker, see [`Engine::stream`].
pub(super) struct Stream {
    pub(super) fetching: Rc<Fetching>,
    /// Its MIME type, as its first chunk tells once it is here, or as its sender gave it.
    pub(super) mime: String,
    /// The clock of the peer's message it came in, to tell the peer once it is all here; 0 for
    /// this client's own.
    pub(super) clock: u64,
}

impl Engine {
    /// A URL that plays the attachment `pointer`, in the chat with `peer`, as it is fetched,
    /// through the service worker, see `media-worker.js`: a chunk at a time, as the player asks
    /// for it, so that it plays, and seeks, while it downloads. The peer is told once it is all
    /// here, as when opened, if it is the peer's, sent in its message at `clock`. None if no
    /// service worker controls the page, which then fetches it whole, or if it is malformed. It
    /// plays until [`end_stream`](Self::end_stream).
    pub async fn stream(
        &self,
        peer: PublicKey,
        index: u64,
        pointer: &AttachmentPointer,
        clock: u64,
    ) -> Option<String> {
        if !glue::streaming() {
            return None;
        }
        let fetching = self.fetching(peer, index, pointer).await.ok()?;
        let mut token = [0; 16];
        getrandom::fill(&mut token).ok()?;
        let token = hex(&token);
        let stream = Stream {
            fetching: Rc::new(fetching),
            mime: stream_mime(&pointer.mime),
            clock,
        };
        self.streams.borrow_mut().insert(token.clone(), stream);
        Some(format!("/media/{token}"))
    }

    /// End the stream at `url`, as its player went.
    pub fn end_stream(&self, url: &str) {
        if let Some(token) = url.strip_prefix("/media/") {
            self.streams.borrow_mut().remove(token);
        }
    }

    /// The first chunk of the stream at `url`, e.g. to read the tags of audio from.
    pub async fn stream_head(&self, url: &str) -> Option<Rc<Vec<u8>>> {
        let token = url.strip_prefix("/media/")?;
        self.stream_chunk(token, 0).await.ok().flatten()
    }

    /// Answer the service worker's `request` for a stream's bytes.
    pub(super) async fn serve_media(&self, request: MediaRequest) {
        match self
            .media_range(&request.token, request.start, request.end)
            .await
        {
            Ok((size, mime, bytes)) => request.reply(Ok((size, &mime, &bytes))),
            Err(status) => request.reply(Err(status)),
        }
    }

    /// The bytes of the stream `token` from `start`, to `end` at most, as far as the chunk they
    /// start in goes, with its size and MIME type; or the HTTP status that says why not.
    async fn media_range(
        &self,
        token: &str,
        start: u64,
        end: Option<u64>,
    ) -> Result<(u64, String, Vec<u8>), u16> {
        const GONE: u16 = 404;
        const OUT_OF_RANGE: u16 = 416;
        let size = self
            .streams
            .borrow()
            .get(token)
            .map(|stream| stream.fetching.size)
            .ok_or(GONE)?;
        if start >= size || end.is_some_and(|end| end < start) {
            return Err(OUT_OF_RANGE);
        }
        let index = u32::try_from(start / CHUNK_SIZE as u64).map_err(|_| OUT_OF_RANGE)?;
        let chunk = match self.stream_chunk(token, index).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Err(GONE),
            // E.g. its sender cancelled it.
            Err(_) => return Err(502),
        };
        let from = start - u64::from(index) * CHUNK_SIZE as u64;
        let to = end.map_or(u64::MAX, |end| {
            from.saturating_add(end - start).saturating_add(1)
        });
        let bytes = chunk
            .get(from as usize..(to.min(chunk.len() as u64)) as usize)
            .filter(|bytes| !bytes.is_empty())
            .ok_or(OUT_OF_RANGE)?
            .to_vec();
        let mime = self
            .streams
            .borrow()
            .get(token)
            .map(|stream| stream.mime.clone())
            .ok_or(GONE)?;
        Ok((size, mime, bytes))
    }

    /// Chunk `index` of the stream `token`, decrypted: one decrypted lately, or from this
    /// client's own file, while on the page that chose it, or else as [`chunk`](Self::chunk)
    /// has it. Once all its chunks are here, as one came from the server now, the peer is told.
    /// None if the stream ended.
    async fn stream_chunk(&self, token: &str, index: u32) -> Result<Option<Rc<Vec<u8>>>, String> {
        let (fetching, clock) = loop {
            let Some((fetching, clock)) = self
                .streams
                .borrow()
                .get(token)
                .map(|stream| (stream.fetching.clone(), stream.clock))
            else {
                return Ok(None);
            };
            let chunk_of = (fetching.peer, fetching.id, fetching.key_hash, index);
            if let Some(chunk) = self.decrypted_chunk(&chunk_of) {
                return Ok(Some(chunk));
            }
            let waiting = match self.loading.borrow_mut().entry(chunk_of) {
                hash_map::Entry::Occupied(mut waiters) => {
                    let (done, waiting) = oneshot::channel();
                    waiters.get_mut().push(done);
                    waiting
                }
                hash_map::Entry::Vacant(vacant) => {
                    vacant.insert(vec![]);
                    break (fetching, clock);
                }
            };
            // Then among those decrypted, unless fetching it failed, or stopped as its stream
            // ended: then fetched here.
            let _ = waiting.await;
        };
        let chunk_of = (fetching.peer, fetching.id, fetching.key_hash, index);
        let loaded = self.load_stream_chunk(token, index, &fetching).await;
        // Among those decrypted, if it came: its waiters wake as their senders go.
        self.loading.borrow_mut().remove(&chunk_of);
        let Some((chunk, fetched)) = loaded? else {
            return Ok(None);
        };
        if fetched
            && clock > 0
            && self.all_kept(&fetching).await
            && let Err(e) = self.downloaded(fetching.peer, clock).await
        {
            self.ui.link.set(Link::Offline(e));
        }
        Ok(Some(chunk))
    }

    /// The chunk `chunk_of`, if the streams decrypted it lately, which keeps it longer.
    fn decrypted_chunk(&self, chunk_of: &ChunkOf) -> Option<Rc<Vec<u8>>> {
        let mut decrypted = self.decrypted.borrow_mut();
        let at = decrypted.iter().position(|(of, _)| of == chunk_of)?;
        let kept = decrypted.remove(at)?;
        let chunk = kept.1.clone();
        decrypted.push_back(kept);
        Some(chunk)
    }

    /// Chunk `index` of the stream `token`, which fetches `fetching`, as
    /// [`stream_chunk`](Self::stream_chunk) has it, kept among those decrypted, and whether it
    /// came from the server.
    async fn load_stream_chunk(
        &self,
        token: &str,
        index: u32,
        fetching: &Fetching,
    ) -> Result<Option<(Rc<Vec<u8>>, bool)>, String> {
        let file = self
            .files
            .borrow()
            .get(&(fetching.peer, fetching.id, fetching.key_hash))
            .cloned();
        let (plaintext, fetched) = match file {
            Some(file) => (read_chunk(&file, index, fetching.size).await?, false),
            None => {
                let plays = || self.streams.borrow().contains_key(token);
                match self.chunk(fetching, index, Waiter::Chat(&plays)).await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => return Ok(None),
                    Err(FetchError::NotFound(msg)) => {
                        let _ = self
                            .note_gone_by_id(&fetching.peer, Some(fetching.index), &fetching.id)
                            .await;
                        return Err(msg);
                    }
                    Err(FetchError::Other(msg)) => return Err(msg),
                }
            }
        };
        let chunk = Rc::new(plaintext);
        let mut decrypted = self.decrypted.borrow_mut();
        decrypted.push_back((
            (fetching.peer, fetching.id, fetching.key_hash, index),
            chunk.clone(),
        ));
        if decrypted.len() > CHUNKS_DECRYPTED_KEPT {
            decrypted.pop_front();
        }
        // Served from the page's origin: only ever as video or audio.
        if index == 0
            && let Some(stream) = self.streams.borrow_mut().get_mut(token)
            && let Some(mime) = preview::media_mime(&fetching.name, &stream.mime, &chunk)
                .filter(|mime| mime.starts_with("video/") || mime.starts_with("audio/"))
        {
            stream.mime = mime.to_string();
        }
        Ok(Some((chunk, fetched)))
    }

    /// Whether all the chunks of the attachment `fetching` fetches are kept here.
    async fn all_kept(&self, fetching: &Fetching) -> bool {
        let guard = self.inner.lock().await;
        let Some(inner) = guard.as_ref() else {
            return false;
        };
        inner
            .vault
            .chunks_kept(&fetching.peer, &fetching.id)
            .await
            .is_ok_and(|kept| kept >= fetching.chunks)
    }
}

/// The MIME type a stream is served as until its first bytes tell, from the page's origin: the
/// type its sender gave, if it is a plain video or audio type, else none in particular.
fn stream_mime(mime: &str) -> String {
    let mime = mime.to_lowercase();
    let plain = mime
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/+-.".contains(&byte));
    if plain && (mime.starts_with("video/") || mime.starts_with("audio/")) {
        mime
    } else {
        "application/octet-stream".to_string()
    }
}
