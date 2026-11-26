//! The attachment service: files too large for a message, encrypted by their sender under a key
//! of their own and uploaded in chunks of at most [`MAX_CHUNK_SIZE`], which the recipients
//! download. A message carries the key and the attachment's ID, so the server only sees
//! ciphertext.
//!
//! An attachment has two tokens:
//! - its **upload token**, random, which the server gives the uploader alone as the upload
//!   starts, uploads its chunks; the uploader forgets it once they are up;
//! - its **delete token**, which the peers derive from the attachment's key, deletes it, at any
//!   time, whoever of them does: a recipient that does not want it spares the uploader the rest.
//!
//! The upload token deletes it too. The server keeps only their SHA-256, and nothing about an
//! upload is signed, nor names its uploader: holding the delete token shows only that one knew
//! the key, which every peer of the chat does. Who may start an upload is up to the server, e.g.
//! those signed in to it.
//!
//! A chunk is uploaded once: uploading it again, e.g. as the reply to its upload was lost, keeps
//! the first copy.
//!
//! An attachment can be downloaded while it is uploaded: a chunk not uploaded yet is a
//! [`GetChunkResponse`] that says so, while an attachment that is gone, expired or deleted,
//! fails with [`ErrorKind::NotFound`](crate::ErrorKind::NotFound).

use core::fmt;

use crate::error::Result;

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/attachment.v1.rs"));
}

pub use proto::*;
#[cfg(feature = "server")]
pub use server::{AttachmentLimits, AttachmentServer};

/// The smallest valid encrypted chunk, in bytes (a 16-byte AES-256-GCM tag over empty plaintext).
pub const MIN_CHUNK_SIZE: usize = 16;
/// The largest chunk, in bytes, encrypted.
pub const MAX_CHUNK_SIZE: usize = 2 << 20;
/// Most chunks of an attachment, unless a server says otherwise: 100 MiB.
pub const DEFAULT_MAX_CHUNKS: u32 = 50;
/// Length of an attachment's ID.
pub const ID_LENGTH: usize = 16;
/// Length of an upload or delete token.
pub const TOKEN_LENGTH: usize = 16;

impl Drop for StartUploadResponse {
    fn drop(&mut self) {
        crate::zeroize_bytes(&mut self.upload_token);
    }
}

impl zeroize::ZeroizeOnDrop for StartUploadResponse {}

impl Drop for PutChunkRequest {
    fn drop(&mut self) {
        crate::zeroize_bytes(&mut self.upload_token);
    }
}

impl zeroize::ZeroizeOnDrop for PutChunkRequest {}

impl Drop for DeleteAttachmentRequest {
    fn drop(&mut self) {
        crate::zeroize_bytes(&mut self.token);
    }
}

impl zeroize::ZeroizeOnDrop for DeleteAttachmentRequest {}

impl fmt::Debug for StartUploadResponse {
    /// Redacts `upload_token`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartUploadResponse")
            .field("id", &self.id)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PutChunkRequest {
    /// Redacts `upload_token`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PutChunkRequest")
            .field("id", &self.id)
            .field("index", &self.index)
            .field("data_len", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DeleteAttachmentRequest {
    /// Redacts `token`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeleteAttachmentRequest")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Client side of the attachment service.
#[trait_variant::make(Attachments: Send)]
pub trait LocalAttachments {
    /// Start uploading an attachment.
    async fn start_upload(&self, request: StartUploadRequest) -> Result<StartUploadResponse>;
    /// Upload a chunk; uploading it again keeps the first copy.
    async fn put_chunk(&self, request: PutChunkRequest) -> Result<PutChunkResponse>;
    /// Download a chunk, or learn that it is not uploaded yet.
    async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse>;
    /// Delete an attachment, uploaded or not, with its upload or delete token.
    async fn delete_attachment(
        &self,
        request: DeleteAttachmentRequest,
    ) -> Result<DeleteAttachmentResponse>;
}

#[cfg(feature = "server")]
mod server {
    use bytes::Bytes;
    use sha2::{Digest, Sha256};
    use storage::{LocalAttachmentStore, StoredAttachment, UPLOADED_NOTED};
    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;

    use super::*;
    use crate::{error::ErrorKind, fixed, try_random};

    /// Limits of an [`AttachmentServer`].
    #[derive(Debug, Clone, Copy)]
    pub struct AttachmentLimits {
        /// Most chunks of an attachment, so it is at most this many times [`MAX_CHUNK_SIZE`].
        /// Must be between `1` and [`storage::UPLOADED_NOTED`] (`53`) inclusive.
        pub max_chunks: u32,
        /// How long the store keeps an attachment from its upload's start, if it says, which
        /// the uploader learns, and tells the recipients.
        pub retention: Option<core::time::Duration>,
    }

    impl Default for AttachmentLimits {
        fn default() -> Self {
            Self {
                max_chunks: DEFAULT_MAX_CHUNKS,
                retention: None,
            }
        }
    }

    /// Builder for [`AttachmentServer`], validating limits at construction.
    #[derive(Debug)]
    pub struct AttachmentServerBuilder<S> {
        store: S,
        limits: AttachmentLimits,
    }

    impl<S> AttachmentServerBuilder<S> {
        /// Sets the limits of the server.
        pub fn limits(mut self, limits: AttachmentLimits) -> Self {
            self.limits = limits;
            self
        }

        /// Builds the [`AttachmentServer`], failing with [`ErrorKind::LimitExceeded`] if
        /// `limits.max_chunks > storage::UPLOADED_NOTED` (`53`) or [`ErrorKind::Malformed`] if
        /// `limits.max_chunks == 0`.
        pub fn build(self) -> Result<AttachmentServer<S>> {
            if self.limits.max_chunks == 0 {
                return Err(ErrorKind::Malformed.into());
            }
            if self.limits.max_chunks > UPLOADED_NOTED {
                return Err(ErrorKind::LimitExceeded.into());
            }
            Ok(AttachmentServer {
                store: self.store,
                limits: self.limits,
            })
        }
    }

    /// The attachment server's logic, over any attachment store.
    ///
    /// [`AttachmentServer::new`] gives it the default limits, and [`AttachmentServer::builder`]
    /// can set and validate them: `AttachmentServer::builder(store).limits(limits).build()?`.
    #[derive(Debug)]
    pub struct AttachmentServer<S> {
        store: S,
        limits: AttachmentLimits,
    }

    impl<S> AttachmentServer<S> {
        /// A server over `store`, with the default limits.
        pub fn new(store: S) -> Self {
            Self::builder(store)
                .build()
                .expect("DEFAULT_MAX_CHUNKS is within storage::UPLOADED_NOTED")
        }

        /// Starts building a server over `store` with custom [`AttachmentLimits`].
        pub fn builder(store: S) -> AttachmentServerBuilder<S> {
            AttachmentServerBuilder {
                store,
                limits: AttachmentLimits::default(),
            }
        }
    }

    impl<S: LocalAttachmentStore> AttachmentServer<S> {
        /// The attachment `id`, which must exist.
        async fn attachment(&self, id: &[u8; ID_LENGTH]) -> Result<StoredAttachment> {
            Ok(self
                .store
                .attachment(id)
                .await?
                .ok_or(ErrorKind::NotFound)?)
        }
    }

    impl<S: LocalAttachmentStore> LocalAttachments for AttachmentServer<S> {
        /// Check the request and add the attachment, under a random ID, with a random upload
        /// token.
        async fn start_upload(&self, request: StartUploadRequest) -> Result<StartUploadResponse> {
            let now = crate::now_millis();
            let delete_hash = fixed(&request.delete_hash)?;
            let chunks = request.chunks;
            drop(request);
            if chunks == 0 {
                return Err(ErrorKind::Malformed.into());
            }
            if chunks > self.limits.max_chunks.min(UPLOADED_NOTED) {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let token = Zeroizing::new(try_random::<TOKEN_LENGTH>()?);
            let attachment = StoredAttachment {
                id: try_random()?,
                chunks,
                token_hash: Sha256::digest(token.as_slice()).into(),
                delete_hash,
                uploaded: 0,
            };
            let id = attachment.id;
            // 128 random bits do not collide, but a store that says so is believed.
            if !self.store.add_attachment(attachment).await? {
                return Err(ErrorKind::Server.into());
            }
            let expires = self.limits.retention.map_or(0, |retention| {
                now.saturating_add(u64::try_from(retention.as_millis()).unwrap_or(u64::MAX))
                    .min(crate::MAX_SAFE_INTEGER)
            });
            Ok(StartUploadResponse {
                id: Bytes::copy_from_slice(&id),
                upload_token: Bytes::copy_from_slice(token.as_slice()),
                expires,
            })
        }

        /// Store a chunk, if the upload token is the attachment's and the chunk is not stored
        /// already: one uploaded again keeps its first copy.
        async fn put_chunk(&self, mut request: PutChunkRequest) -> Result<PutChunkResponse> {
            // Destructure and drop sibling `Bytes` handles BEFORE any `.await` so `data` does not
            // share the underlying decoded request buffer across async calls.
            let data = core::mem::take(&mut request.data);
            let id_bytes = core::mem::take(&mut request.id);
            let mut upload_token = core::mem::take(&mut request.upload_token);
            let index = request.index;
            drop(request);

            if data.len() > MAX_CHUNK_SIZE {
                crate::zeroize_bytes(&mut upload_token);
                return Err(ErrorKind::LimitExceeded.into());
            }
            let id_res: Result<[u8; ID_LENGTH]> = fixed(&id_bytes);
            drop(id_bytes);
            let token_hash = <[u8; 32]>::from(Sha256::digest(&upload_token));
            crate::zeroize_bytes(&mut upload_token);
            drop(upload_token);
            let id = id_res?;

            let attachment = self.attachment(&id).await?;
            if !bool::from(token_hash.ct_eq(&attachment.token_hash)) {
                return Err(ErrorKind::InvalidSignature.into());
            }
            if index >= attachment.chunks || data.len() < MIN_CHUNK_SIZE {
                return Err(ErrorKind::Malformed.into());
            }
            // Noted as uploaded, it stays as it is, though it expired since; the store keeps the
            // first copy of the others, beyond what is noted.
            if attachment.was_uploaded(index) {
                return Ok(PutChunkResponse {});
            }
            self.store.put_chunk(&attachment.id, index, data).await?;
            Ok(PutChunkResponse {})
        }

        /// A chunk, as uploaded, or that it is not uploaded yet. One uploaded and gone since,
        /// as the store's lifecycle rules deleted it, is not found: it expired.
        async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse> {
            let id: [u8; ID_LENGTH] = fixed(&request.id)?;
            let index = request.index;
            drop(request);
            let attachment = self.attachment(&id).await?;
            if index >= attachment.chunks {
                return Err(ErrorKind::Malformed.into());
            }
            match self.store.chunk(&attachment.id, index).await? {
                Some(data) => Ok(GetChunkResponse {
                    data,
                    uploaded: true,
                }),
                None if attachment.was_uploaded(index) => Err(ErrorKind::NotFound.into()),
                None => {
                    // Re-check existence in case the attachment was concurrently deleted between
                    // `attachment()` and `chunk()` so callers see `NotFound` instead of spinning
                    // on `uploaded: false`.
                    if self.store.attachment(&attachment.id).await?.is_none() {
                        return Err(ErrorKind::NotFound.into());
                    }
                    Ok(GetChunkResponse::default())
                }
            }
        }

        /// Delete the attachment, if the token is its upload or delete token.
        async fn delete_attachment(
            &self,
            mut request: DeleteAttachmentRequest,
        ) -> Result<DeleteAttachmentResponse> {
            let id_bytes = core::mem::take(&mut request.id);
            let mut token = core::mem::take(&mut request.token);
            drop(request);
            let id_res: Result<[u8; ID_LENGTH]> = fixed(&id_bytes);
            drop(id_bytes);
            let hash = <[u8; 32]>::from(Sha256::digest(&token));
            crate::zeroize_bytes(&mut token);
            drop(token);
            let id = id_res?;

            let attachment = self.attachment(&id).await?;
            let matches = hash.ct_eq(&attachment.token_hash) | hash.ct_eq(&attachment.delete_hash);
            if !bool::from(matches) {
                return Err(ErrorKind::InvalidSignature.into());
            }
            self.store.delete_attachment(&attachment.id).await?;
            Ok(DeleteAttachmentResponse {})
        }
    }

    #[cfg(test)]
    mod test {
        use storage::MemoryStore;

        use super::*;

        fn now() -> u64 {
            web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        }

        #[tokio::test]
        async fn upload_and_download() {
            let server = AttachmentServer::builder(MemoryStore::default())
                .limits(AttachmentLimits {
                    max_chunks: 2,
                    retention: Some(core::time::Duration::from_secs(60)),
                })
                .build()
                .unwrap();
            // The delete token, which the peers derive from the attachment's key.
            let delete_token = Bytes::from_static(&[7; TOKEN_LENGTH]);
            let start = |chunks| StartUploadRequest {
                chunks,
                delete_hash: Bytes::from(Sha256::digest(&delete_token).to_vec()),
            };
            // Too many chunks, or none, or no delete hash.
            for (request, kind) in [
                (start(3), ErrorKind::LimitExceeded),
                (start(0), ErrorKind::Malformed),
                (
                    StartUploadRequest {
                        chunks: 2,
                        delete_hash: Bytes::new(),
                    },
                    ErrorKind::Malformed,
                ),
            ] {
                assert_eq!(server.start_upload(request).await.unwrap_err().kind(), kind);
            }
            let started = server.start_upload(start(2)).await.unwrap();
            // It says when it expires, a minute on.
            assert!(started.expires.abs_diff(now() + 60_000) < 1000);
            let put = |index, upload_token: &Bytes, data: Vec<u8>| PutChunkRequest {
                id: started.id.clone(),
                upload_token: upload_token.clone(),
                index,
                data: Bytes::from(data),
            };
            let second_chunk = b"second-encrypted-chunk";
            let first_chunk = b"first-encrypted-chunk!";
            server
                .put_chunk(put(1, &started.upload_token, second_chunk.to_vec()))
                .await
                .unwrap();
            // Only with the upload token, within the chunks, and each between MIN and MAX size.
            let wrong = Bytes::from_static(&[0; TOKEN_LENGTH]);
            for (request, kind) in [
                (
                    put(0, &wrong, vec![0; MIN_CHUNK_SIZE]),
                    ErrorKind::InvalidSignature,
                ),
                (
                    put(2, &started.upload_token, vec![0; MIN_CHUNK_SIZE]),
                    ErrorKind::Malformed,
                ),
                (
                    put(0, &started.upload_token, vec![0; MIN_CHUNK_SIZE - 1]),
                    ErrorKind::Malformed,
                ),
                (
                    put(0, &started.upload_token, vec![0; MAX_CHUNK_SIZE + 1]),
                    ErrorKind::LimitExceeded,
                ),
            ] {
                assert_eq!(server.put_chunk(request).await.unwrap_err().kind(), kind);
            }

            let get = |index| GetChunkRequest {
                id: started.id.clone(),
                index,
            };
            let second = server.get_chunk(get(1)).await.unwrap();
            assert!(second.uploaded);
            assert_eq!(second.data, &second_chunk[..]);
            // Uploaded again, even with its upload token, it stays as it was downloaded.
            server
                .put_chunk(put(
                    1,
                    &started.upload_token,
                    b"changed-encrypted-data".to_vec(),
                ))
                .await
                .unwrap();
            assert_eq!(
                server.get_chunk(get(1)).await.unwrap().data,
                &second_chunk[..]
            );
            // Not uploaded yet, or never: no such chunk.
            assert!(!server.get_chunk(get(0)).await.unwrap().uploaded);
            assert_eq!(
                server.get_chunk(get(2)).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );
            // The delete token uploads nothing.
            assert_eq!(
                server
                    .put_chunk(put(0, &delete_token, first_chunk.to_vec()))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );

            // Deleted with the delete token, before its upload is done, it is gone, and its
            // upload stops.
            let delete = |token: &Bytes| DeleteAttachmentRequest {
                id: started.id.clone(),
                token: token.clone(),
            };
            assert_eq!(
                server
                    .delete_attachment(delete(&wrong))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            server
                .delete_attachment(delete(&delete_token))
                .await
                .unwrap();
            assert_eq!(
                server.get_chunk(get(1)).await.unwrap_err().kind(),
                ErrorKind::NotFound
            );
            assert_eq!(
                server
                    .put_chunk(put(0, &started.upload_token, first_chunk.to_vec()))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::NotFound
            );

            // The upload token deletes one too.
            let started = server.start_upload(start(1)).await.unwrap();
            let delete = DeleteAttachmentRequest {
                id: started.id.clone(),
                token: started.upload_token.clone(),
            };
            server.delete_attachment(delete).await.unwrap();
        }

        #[tokio::test]
        async fn expires_clamped_debug_redacts_tokens_and_concurrent_delete_returns_not_found() {
            // 1. Huge retention clamps `expires` to MAX_SAFE_INTEGER.
            let server = AttachmentServer::builder(MemoryStore::default())
                .limits(AttachmentLimits {
                    max_chunks: 2,
                    retention: Some(core::time::Duration::from_secs(u64::MAX)),
                })
                .build()
                .unwrap();
            let delete_token = Bytes::from_static(&[0xAB; TOKEN_LENGTH]);
            let started = server
                .start_upload(StartUploadRequest {
                    chunks: 2,
                    delete_hash: Bytes::from(Sha256::digest(&delete_token).to_vec()),
                })
                .await
                .unwrap();
            assert_eq!(started.expires, crate::MAX_SAFE_INTEGER);

            // 2. Debug output redacts upload_token and delete token.
            let start_dbg = format!("{started:?}");
            assert!(!start_dbg.contains("upload_token"), "{start_dbg}");
            let put_req = PutChunkRequest {
                id: started.id.clone(),
                upload_token: started.upload_token.clone(),
                index: 0,
                data: Bytes::from_static(&[0xCD; MIN_CHUNK_SIZE]),
            };
            let put_dbg = format!("{put_req:?}");
            assert!(!put_dbg.contains("upload_token"), "{put_dbg}");
            let del_req = DeleteAttachmentRequest {
                id: started.id.clone(),
                token: delete_token.clone(),
            };
            let del_dbg = format!("{del_req:?}");
            assert!(!del_dbg.contains("token"), "{del_dbg}");
            assert!(!del_dbg.contains("171"), "{del_dbg}");

            // 3. Concurrent delete between metadata check and chunk op returns NotFound.
            struct RacingDeleteStore {
                inner: MemoryStore,
                delete_on_put: core::sync::atomic::AtomicBool,
                delete_on_chunk: core::sync::atomic::AtomicBool,
            }

            impl LocalAttachmentStore for RacingDeleteStore {
                async fn add_attachment(&self, a: StoredAttachment) -> storage::Result<bool> {
                    storage::AttachmentStore::add_attachment(&self.inner, a).await
                }
                async fn attachment(
                    &self,
                    id: &[u8; 16],
                ) -> storage::Result<Option<StoredAttachment>> {
                    storage::AttachmentStore::attachment(&self.inner, id).await
                }
                async fn put_chunk(
                    &self,
                    id: &[u8; 16],
                    index: u32,
                    data: Bytes,
                ) -> storage::Result<()> {
                    if self
                        .delete_on_put
                        .swap(false, core::sync::atomic::Ordering::SeqCst)
                    {
                        storage::AttachmentStore::delete_attachment(&self.inner, id).await?;
                    }
                    storage::AttachmentStore::put_chunk(&self.inner, id, index, data).await
                }
                async fn chunk(&self, id: &[u8; 16], index: u32) -> storage::Result<Option<Bytes>> {
                    if self
                        .delete_on_chunk
                        .swap(false, core::sync::atomic::Ordering::SeqCst)
                    {
                        storage::AttachmentStore::delete_attachment(&self.inner, id).await?;
                    }
                    storage::AttachmentStore::chunk(&self.inner, id, index).await
                }
                async fn delete_attachment(&self, id: &[u8; 16]) -> storage::Result<()> {
                    storage::AttachmentStore::delete_attachment(&self.inner, id).await
                }
            }

            let racing = AttachmentServer::new(RacingDeleteStore {
                inner: MemoryStore::default(),
                delete_on_put: core::sync::atomic::AtomicBool::new(true),
                delete_on_chunk: core::sync::atomic::AtomicBool::new(false),
            });
            let s1 = racing
                .start_upload(StartUploadRequest {
                    chunks: 1,
                    delete_hash: Bytes::from(Sha256::digest(&delete_token).to_vec()),
                })
                .await
                .unwrap();
            assert_eq!(
                racing
                    .put_chunk(PutChunkRequest {
                        id: s1.id.clone(),
                        upload_token: s1.upload_token.clone(),
                        index: 0,
                        data: Bytes::from_static(&[0xEF; MIN_CHUNK_SIZE]),
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::NotFound
            );

            let racing_get = AttachmentServer::new(RacingDeleteStore {
                inner: MemoryStore::default(),
                delete_on_put: core::sync::atomic::AtomicBool::new(false),
                delete_on_chunk: core::sync::atomic::AtomicBool::new(true),
            });
            let s2 = racing_get
                .start_upload(StartUploadRequest {
                    chunks: 1,
                    delete_hash: Bytes::from(Sha256::digest(&delete_token).to_vec()),
                })
                .await
                .unwrap();
            assert_eq!(
                racing_get
                    .get_chunk(GetChunkRequest {
                        id: s2.id.clone(),
                        index: 0,
                    })
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::NotFound
            );
        }

        #[test]
        fn rejects_max_chunks_above_uploaded_noted() {
            assert!(
                AttachmentServer::builder(MemoryStore::default())
                    .limits(AttachmentLimits {
                        max_chunks: UPLOADED_NOTED,
                        ..AttachmentLimits::default()
                    })
                    .build()
                    .is_ok()
            );
            assert_eq!(
                AttachmentServer::builder(MemoryStore::default())
                    .limits(AttachmentLimits {
                        max_chunks: UPLOADED_NOTED + 1,
                        ..AttachmentLimits::default()
                    })
                    .build()
                    .unwrap_err()
                    .kind(),
                ErrorKind::LimitExceeded
            );
            assert_eq!(
                AttachmentServer::builder(MemoryStore::default())
                    .limits(AttachmentLimits {
                        max_chunks: 0,
                        ..AttachmentLimits::default()
                    })
                    .build()
                    .unwrap_err()
                    .kind(),
                ErrorKind::Malformed
            );
        }
    }
}

#[cfg(test)]
mod token_zeroize_tests {
    use bytes::Bytes;
    use prost::Message as _;
    use zeroize::ZeroizeOnDrop;

    use super::*;

    #[test]
    fn token_messages_implement_zeroize_on_drop_and_wipe_unique_buffers() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<StartUploadResponse>();
        assert_zeroize_on_drop::<PutChunkRequest>();
        assert_zeroize_on_drop::<DeleteAttachmentRequest>();

        // Uniquely owned Bytes (copy_from_slice) and prost-decoded Bytes convert into BytesMut
        // in place, so `zeroize_bytes` overwrites the backing token memory.
        let mut owned = Bytes::copy_from_slice(&[0xAA; TOKEN_LENGTH]);
        let clone = owned.clone();
        drop(clone);
        assert!(owned.clone().try_into_mut().is_err());
        let unique = core::mem::take(&mut owned);
        assert!(unique.try_into_mut().is_ok());

        let encoded = StartUploadResponse {
            id: Bytes::copy_from_slice(&[0x11; ID_LENGTH]),
            upload_token: Bytes::copy_from_slice(&[0xBB; TOKEN_LENGTH]),
            expires: 42,
        }
        .encode_to_vec();
        let mut decoded = StartUploadResponse::decode(encoded.as_slice()).unwrap();
        let decoded_token = core::mem::take(&mut decoded.upload_token);
        assert!(decoded_token.try_into_mut().is_ok());

        // Static buffers detach cleanly without panicking.
        let mut static_bytes = Bytes::from_static(&[0xCC; TOKEN_LENGTH]);
        crate::zeroize_bytes(&mut static_bytes);
        assert!(static_bytes.is_empty());
    }
}
