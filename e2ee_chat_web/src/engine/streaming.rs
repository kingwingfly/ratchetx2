//! Range requests and decrypted chunk caching for streaming media.

use super::attachments::{FetchError, Fetching, Waiter, read_chunk};
use super::{CHUNKS_DECRYPTED_KEPT, ChunkOf, DecryptedChunk, Engine};
use crate::content::AttachmentPointer;
use crate::glue::{MediaError, MediaRange, MediaRequest};
use crate::state::Link;
use crate::util::hex;
use crate::{glue, preview};
use futures_channel::oneshot;
use leptos::prelude::*;
use session::PublicKey;
use session::attachment::CHUNK_SIZE;
use std::collections::hash_map;
use std::rc::Rc;
use zeroize::Zeroizing;

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
    pub async fn stream_head(&self, url: &str) -> Option<DecryptedChunk> {
        let token = url.strip_prefix("/media/")?;
        self.stream_chunk(token, 0, &|| false).await.ok().flatten()
    }

    /// Answer the service worker's `request` for a stream's bytes.
    pub(super) async fn serve_media(&self, request: MediaRequest) {
        if request.is_aborted() {
            return;
        }
        let reply = {
            let aborted = || request.is_aborted();
            self.media_range(&request.token, &request.range, &aborted)
                .await
        };
        if request.is_aborted() {
            return;
        }
        match reply {
            Ok((size, start, mime, bytes)) => request.reply(Ok((size, start, &mime, &bytes))),
            Err(err) => request.reply(Err(err)),
        }
    }

    /// The bytes of the stream `token` for `range`, as far as the chunk they start in goes, with
    /// total size, resolved start offset, and MIME type; or the HTTP error that says why not.
    async fn media_range(
        &self,
        token: &str,
        range: &MediaRange,
        aborted: &dyn Fn() -> bool,
    ) -> Result<(u64, u64, String, Vec<u8>), MediaError> {
        const GONE: u16 = 404;
        if aborted() {
            return Err(MediaError::Status(GONE));
        }
        let size = self
            .streams
            .borrow()
            .get(token)
            .map(|stream| stream.fetching.size)
            .ok_or(MediaError::Status(GONE))?;
        let (start, end) = match *range {
            MediaRange::Whole => {
                if size == 0 {
                    let mime = self
                        .streams
                        .borrow()
                        .get(token)
                        .map(|stream| stream.mime.clone())
                        .ok_or(MediaError::Status(GONE))?;
                    return Ok((0, 0, mime, Vec::new()));
                }
                (0, None)
            }
            MediaRange::Invalid => return Err(MediaError::OutOfRange { size }),
            MediaRange::Suffix(suffix) => {
                if suffix == 0 || size == 0 {
                    return Err(MediaError::OutOfRange { size });
                }
                (size.saturating_sub(suffix), Some(size - 1))
            }
            MediaRange::From { start, end } => {
                if size == 0 || start >= size || end.is_some_and(|end| end < start) {
                    return Err(MediaError::OutOfRange { size });
                }
                (start, end)
            }
        };
        let index = u32::try_from(start / CHUNK_SIZE as u64)
            .map_err(|_| MediaError::OutOfRange { size })?;
        let chunk = match self.stream_chunk(token, index, aborted).await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return Err(MediaError::Status(GONE)),
            // E.g. its sender cancelled it.
            Err(_) => return Err(MediaError::Status(502)),
        };
        let chunk_base = u64::from(index) * CHUNK_SIZE as u64;
        let from = start - chunk_base;
        let available = size.saturating_sub(chunk_base).min(chunk.len() as u64);
        let to = end.map_or(available, |end| {
            from.saturating_add(end - start)
                .saturating_add(1)
                .min(available)
        });
        let bytes = chunk
            .get(from as usize..to as usize)
            .filter(|bytes| !bytes.is_empty())
            .ok_or(MediaError::OutOfRange { size })?
            .to_vec();
        let mime = self
            .streams
            .borrow()
            .get(token)
            .map(|stream| stream.mime.clone())
            .ok_or(MediaError::Status(GONE))?;
        Ok((size, start, mime, bytes))
    }

    /// Chunk `index` of the stream `token`, decrypted: one decrypted lately, or from this
    /// client's own file, while on the page that chose it, or else as [`chunk`](Self::chunk)
    /// has it. Once all its chunks are here, as one came from the server now, the peer is told.
    /// None if the stream ended or the request was aborted.
    async fn stream_chunk(
        &self,
        token: &str,
        index: u32,
        aborted: &dyn Fn() -> bool,
    ) -> Result<Option<DecryptedChunk>, String> {
        let (fetching, clock) = loop {
            if aborted() {
                return Ok(None);
            }
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
                if index == 0 {
                    self.sniff_stream_mime(token, &fetching, &chunk);
                }
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
        // Ensure cancelled or panicking range requests always remove `chunk_of` and wake waiters.
        let loading_guard = scopeguard::guard(chunk_of, |key| {
            self.loading.borrow_mut().remove(&key);
        });
        let loaded = self
            .load_stream_chunk(token, index, &fetching, aborted)
            .await;
        drop(loading_guard);
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

    /// Update the stream's served MIME type from chunk 0's magic bytes (only video or audio, as
    /// streams are served from the page's origin).
    fn sniff_stream_mime(&self, token: &str, fetching: &Fetching, chunk: &[u8]) {
        if let Some(stream) = self.streams.borrow_mut().get_mut(token)
            && let Some(mime) = preview::media_mime(&fetching.name, &stream.mime, chunk)
                .filter(|mime| mime.starts_with("video/") || mime.starts_with("audio/"))
        {
            stream.mime = mime.to_string();
        }
    }

    /// The chunk `chunk_of`, if the streams decrypted it lately, which keeps it longer.
    fn decrypted_chunk(&self, chunk_of: &ChunkOf) -> Option<DecryptedChunk> {
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
        aborted: &dyn Fn() -> bool,
    ) -> Result<Option<(DecryptedChunk, bool)>, String> {
        let file = self
            .files
            .borrow()
            .get(&(fetching.peer, fetching.id, fetching.key_hash))
            .cloned();
        let (plaintext, fetched) = match file {
            Some(file) => (read_chunk(&file, index, fetching.size).await?, false),
            None => {
                let plays = || !aborted() && self.streams.borrow().contains_key(token);
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
        let chunk = Rc::new(Zeroizing::new(plaintext));
        let mut decrypted = self.decrypted.borrow_mut();
        decrypted.push_back((
            (fetching.peer, fetching.id, fetching.key_hash, index),
            chunk.clone(),
        ));
        if decrypted.len() > CHUNKS_DECRYPTED_KEPT {
            decrypted.pop_front();
        }
        drop(decrypted);
        // Served from the page's origin: only ever as video or audio.
        if index == 0 {
            self.sniff_stream_mime(token, fetching, &chunk);
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

/// Whether `byte` is an RFC 9110 HTTP token character (`tchar`).
fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Validate optional RFC 9110 media-type parameters (e.g. `codecs=avc1`, `codecs="avc1, mp4a"`),
/// rejecting control characters or malformed syntax.
fn valid_mime_params(mut rest: &str) -> bool {
    while !rest.is_empty() {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            return true;
        }
        let Some((name, after_eq)) = rest.split_once('=') else {
            return false;
        };
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            return false;
        }
        let after_eq = after_eq.trim_start_matches([' ', '\t']);
        if let Some(mut quoted) = after_eq.strip_prefix('"') {
            let mut closed = false;
            let mut escaped = false;
            let mut end_idx = 0;
            for (idx, ch) in quoted.char_indices() {
                if escaped {
                    if ch < ' ' && ch != '\t' || ch == '\x7f' {
                        return false;
                    }
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    closed = true;
                    end_idx = idx + 1;
                    break;
                } else if ch < ' ' && ch != '\t' || ch == '\x7f' {
                    return false;
                }
            }
            if !closed {
                return false;
            }
            quoted = quoted[end_idx..].trim_start_matches([' ', '\t']);
            if quoted.is_empty() {
                return true;
            }
            let Some(next) = quoted.strip_prefix(';') else {
                return false;
            };
            rest = next;
        } else {
            let (value, next) = match after_eq.split_once(';') {
                Some((v, n)) => (v.trim_end_matches([' ', '\t']), n),
                None => (after_eq.trim_end_matches([' ', '\t']), ""),
            };
            if value.is_empty() || !value.bytes().all(is_http_token_byte) {
                return false;
            }
            rest = next;
        }
    }
    true
}

/// The MIME type a stream is served as until its first bytes tell, from the page's origin: the
/// bare `video/*` or `audio/*` essence its sender gave (accepting valid parameters such as
/// `; codecs=...` and stripping them cleanly), else `application/octet-stream`.
pub(super) fn stream_mime(mime: &str) -> String {
    let (essence, params) = match mime.split_once(';') {
        Some((essence, params)) => (essence.trim(), Some(params)),
        None => (mime.trim(), None),
    };
    if let Some(params) = params
        && !valid_mime_params(params)
    {
        return "application/octet-stream".to_string();
    }
    let essence = essence.to_ascii_lowercase();
    if let Some((kind, subtype)) = essence.split_once('/')
        && matches!(kind, "video" | "audio")
        && !subtype.is_empty()
        && subtype
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
    {
        essence
    } else {
        "application/octet-stream".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::stream_mime;

    #[test]
    fn stream_mime_requires_single_slash_non_empty_media_subtype() {
        assert_eq!(stream_mime("VIDEO/MP4"), "video/mp4");
        assert_eq!(stream_mime("audio/x-matroska"), "audio/x-matroska");
        assert_eq!(stream_mime("video/mp4; codecs=avc1"), "video/mp4");
        assert_eq!(stream_mime("audio/webm; codecs=opus"), "audio/webm");
        assert_eq!(
            stream_mime("video/mp4; codecs=\"avc1.42E01E, mp4a.40.2\""),
            "video/mp4"
        );
        assert_eq!(stream_mime("video/"), "application/octet-stream");
        assert_eq!(stream_mime("audio/"), "application/octet-stream");
        assert_eq!(stream_mime("video/a/b"), "application/octet-stream");
        assert_eq!(stream_mime("text/html"), "application/octet-stream");
        assert_eq!(
            stream_mime("text/html; codecs=avc1"),
            "application/octet-stream"
        );
        assert_eq!(
            stream_mime("video/mp4; badparam"),
            "application/octet-stream"
        );
        assert_eq!(
            stream_mime("video/mp4; codecs=\"unterminated"),
            "application/octet-stream"
        );
        assert_eq!(
            stream_mime("video/mp4; codecs=\"a\r\nX-Bad: 1\""),
            "application/octet-stream"
        );
    }
}
