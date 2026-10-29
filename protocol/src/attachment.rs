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

use crate::error::Result;

#[allow(missing_docs)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/attachment.v1.rs"));
}

pub use proto::*;
#[cfg(feature = "server")]
pub use server::{AttachmentLimits, AttachmentServer};

/// The largest chunk, in bytes, encrypted.
pub const MAX_CHUNK_SIZE: usize = 2 << 20;
/// Most chunks of an attachment, unless a server says otherwise: 100 MiB.
pub const DEFAULT_MAX_CHUNKS: u32 = 50;
/// Length of an attachment's ID.
pub const ID_LENGTH: usize = 16;
/// Length of an upload or delete token.
pub const TOKEN_LENGTH: usize = 16;

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
    use bon::Builder;
    use sha2::{Digest, Sha256};
    use storage::{LocalAttachmentStore, StoredAttachment};

    use bytes::Bytes;

    use super::*;
    use crate::{error::ErrorKind, fixed};

    /// Limits of an [`AttachmentServer`].
    #[derive(Debug, Clone, Copy)]
    pub struct AttachmentLimits {
        /// Most chunks of an attachment, so it is at most this many times [`MAX_CHUNK_SIZE`].
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

    /// The attachment server's logic, over any attachment store.
    ///
    /// [`AttachmentServer::new`] gives it the default limits, and [`AttachmentServer::builder`]
    /// can set them: `AttachmentServer::builder(store).limits(limits).build()`.
    #[derive(Debug, Builder)]
    pub struct AttachmentServer<S> {
        #[builder(start_fn)]
        store: S,
        /// The limits; the default ones unless set.
        #[builder(default)]
        limits: AttachmentLimits,
    }

    impl<S> AttachmentServer<S> {
        /// A server over `store`, with the default limits.
        pub fn new(store: S) -> Self {
            Self::builder(store).build()
        }
    }

    impl<S: LocalAttachmentStore> AttachmentServer<S> {
        /// The attachment `id`, which must exist.
        async fn attachment(&self, id: &[u8]) -> Result<StoredAttachment> {
            let id = fixed(id)?;
            Ok(self
                .store
                .attachment(&id)
                .await?
                .ok_or(ErrorKind::NotFound)?)
        }

        /// The attachment `id`, if `upload_token` is its upload token.
        async fn uploading(&self, id: &[u8], upload_token: &[u8]) -> Result<StoredAttachment> {
            let attachment = self.attachment(id).await?;
            if <[u8; 32]>::from(Sha256::digest(upload_token)) != attachment.token_hash {
                return Err(ErrorKind::InvalidSignature.into());
            }
            Ok(attachment)
        }

        /// The attachment `id`, if `token` is its upload or delete token.
        async fn deletable(&self, id: &[u8], token: &[u8]) -> Result<StoredAttachment> {
            let attachment = self.attachment(id).await?;
            let hash = <[u8; 32]>::from(Sha256::digest(token));
            if hash != attachment.token_hash && hash != attachment.delete_hash {
                return Err(ErrorKind::InvalidSignature.into());
            }
            Ok(attachment)
        }
    }

    impl<S: LocalAttachmentStore> LocalAttachments for AttachmentServer<S> {
        /// Check the request and add the attachment, under a random ID, with a random upload
        /// token.
        async fn start_upload(&self, request: StartUploadRequest) -> Result<StartUploadResponse> {
            let now = web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis() as u64);
            let delete_hash = fixed(&request.delete_hash)?;
            if request.chunks == 0 {
                return Err(ErrorKind::Malformed.into());
            }
            if request.chunks > self.limits.max_chunks {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let token: [u8; TOKEN_LENGTH] = random();
            let attachment = StoredAttachment {
                id: random(),
                chunks: request.chunks,
                token_hash: Sha256::digest(token).into(),
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
            });
            Ok(StartUploadResponse {
                id: Bytes::copy_from_slice(&id),
                upload_token: Bytes::copy_from_slice(&token),
                expires,
            })
        }

        /// Store a chunk, if the upload token is the attachment's and the chunk is not stored
        /// already: one uploaded again keeps its first copy.
        async fn put_chunk(&self, request: PutChunkRequest) -> Result<PutChunkResponse> {
            if request.data.len() > MAX_CHUNK_SIZE {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let attachment = self.uploading(&request.id, &request.upload_token).await?;
            if request.index >= attachment.chunks {
                return Err(ErrorKind::Malformed.into());
            }
            // Noted as uploaded, it stays as it is, though it expired since; the store keeps the
            // first copy of the others, beyond what is noted.
            if attachment.was_uploaded(request.index) {
                return Ok(PutChunkResponse {});
            }
            self.store
                .put_chunk(&attachment.id, request.index, request.data)
                .await?;
            Ok(PutChunkResponse {})
        }

        /// A chunk, as uploaded, or that it is not uploaded yet. One uploaded and gone since,
        /// as the store's lifecycle rules deleted it, is not found: it expired.
        async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse> {
            let attachment = self.attachment(&request.id).await?;
            if request.index >= attachment.chunks {
                return Err(ErrorKind::Malformed.into());
            }
            match self.store.chunk(&attachment.id, request.index).await? {
                Some(data) => Ok(GetChunkResponse {
                    data,
                    uploaded: true,
                }),
                None if attachment.was_uploaded(request.index) => Err(ErrorKind::NotFound.into()),
                None => Ok(GetChunkResponse::default()),
            }
        }

        /// Delete the attachment, if the token is its upload or delete token.
        async fn delete_attachment(
            &self,
            request: DeleteAttachmentRequest,
        ) -> Result<DeleteAttachmentResponse> {
            let attachment = self.deletable(&request.id, &request.token).await?;
            self.store.delete_attachment(&attachment.id).await?;
            Ok(DeleteAttachmentResponse {})
        }
    }

    /// `N` random bytes.
    fn random<const N: usize>() -> [u8; N] {
        let mut bytes = [0; N];
        getrandom::fill(&mut bytes).expect("the system random number generator failed");
        bytes
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
                .build();
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
            server
                .put_chunk(put(1, &started.upload_token, b"second".to_vec()))
                .await
                .unwrap();
            // Only with the upload token, within the chunks, and each at most MAX_CHUNK_SIZE.
            let wrong = Bytes::from_static(&[0; TOKEN_LENGTH]);
            for (request, kind) in [
                (put(0, &wrong, vec![]), ErrorKind::InvalidSignature),
                (put(2, &started.upload_token, vec![]), ErrorKind::Malformed),
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
            assert_eq!(second.data, &b"second"[..]);
            // Uploaded again, even with its upload token, it stays as it was downloaded.
            server
                .put_chunk(put(1, &started.upload_token, b"changed".to_vec()))
                .await
                .unwrap();
            assert_eq!(server.get_chunk(get(1)).await.unwrap().data, &b"second"[..]);
            // Not uploaded yet, or never: no such chunk.
            assert!(!server.get_chunk(get(0)).await.unwrap().uploaded);
            assert_eq!(
                server.get_chunk(get(2)).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );
            // The delete token uploads nothing.
            assert_eq!(
                server
                    .put_chunk(put(0, &delete_token, b"first".to_vec()))
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
                    .put_chunk(put(0, &started.upload_token, b"first".to_vec()))
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
    }
}
