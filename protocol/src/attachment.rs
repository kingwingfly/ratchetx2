//! The attachment service: files too large for a message, encrypted by their sender under a key
//! of their own and uploaded in chunks of at most [`MAX_CHUNK_SIZE`], which the recipients
//! download. A message carries the key and the attachment's ID, so the server only sees
//! ciphertext.
//!
//! Starting an upload is signed like the handshake's requests: the signature covers
//! `"attachment.v1/start-upload"` ‖ identity key ‖ number of chunks (u32, little-endian) ‖
//! timestamp (u64, little-endian), and the server takes it only within
//! [`MAX_CLOCK_SKEW`](crate::MAX_CLOCK_SKEW) of its own clock. It returns a random upload
//! token, which uploading the chunks and cancelling the upload take, and a random ID, which
//! downloading them takes.
//!
//! An attachment can be downloaded while it is uploaded: a chunk not uploaded yet is a
//! [`GetChunkResponse`] that says so, while an attachment that is gone, expired or cancelled,
//! fails with [`ErrorKind::NotFound`](crate::ErrorKind::NotFound).

use bytes::Bytes;
use x3dh::PublicKey;
use xeddsa::XEdDSAPrivateKey;

use crate::{error::Result, verify_recent};

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
/// Length of an upload token.
pub const TOKEN_LENGTH: usize = 16;

/// Client side of the attachment service.
#[trait_variant::make(Attachments: Send)]
pub trait LocalAttachments {
    /// Start uploading an attachment; see [`StartUploadRequest::sign`].
    async fn start_upload(&self, request: StartUploadRequest) -> Result<StartUploadResponse>;
    /// Upload a chunk, or upload it again.
    async fn put_chunk(&self, request: PutChunkRequest) -> Result<PutChunkResponse>;
    /// Download a chunk, or learn that it is not uploaded yet.
    async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse>;
    /// Cancel an upload: the attachment and its chunks go.
    async fn cancel_upload(&self, request: CancelUploadRequest) -> Result<CancelUploadResponse>;
}

impl StartUploadRequest {
    /// A request to upload `chunks` chunks as `identity`, signed by it.
    pub fn sign(identity: &XEdDSAPrivateKey, chunks: u32, timestamp: u64) -> Self {
        let identity_key = identity.compute_public_key().to_bytes();
        let signature = identity.sign(start_upload_message(&identity_key, chunks, timestamp));
        Self {
            identity_key: Bytes::copy_from_slice(&identity_key),
            chunks,
            timestamp,
            signature: Bytes::copy_from_slice(&signature),
        }
    }

    /// The identity key uploading, once the signature by that key verifies and the timestamp is
    /// within [`MAX_CLOCK_SKEW`](crate::MAX_CLOCK_SKEW) of `now`, in milliseconds since the Unix
    /// epoch.
    pub fn verify(&self, now: u64) -> Result<PublicKey> {
        verify_recent(
            &self.identity_key,
            &self.signature,
            self.timestamp,
            now,
            |identity_key| start_upload_message(identity_key, self.chunks, self.timestamp),
        )
    }
}

/// The bytes a start-upload request's signature covers.
fn start_upload_message(identity_key: &PublicKey, chunks: u32, timestamp: u64) -> Vec<u8> {
    let mut message = b"attachment.v1/start-upload".to_vec();
    message.extend(identity_key);
    message.extend(chunks.to_le_bytes());
    message.extend(timestamp.to_le_bytes());
    message
}

#[cfg(feature = "server")]
mod server {
    use bon::Builder;
    use sha2::{Digest, Sha256};
    use storage::{LocalAttachmentStore, StoredAttachment};

    use super::*;
    use crate::{error::ErrorKind, fixed};

    /// Limits of an [`AttachmentServer`].
    #[derive(Debug, Clone, Copy)]
    pub struct AttachmentLimits {
        /// Most chunks of an attachment, so it is at most this many times [`MAX_CHUNK_SIZE`].
        pub max_chunks: u32,
    }

    impl Default for AttachmentLimits {
        fn default() -> Self {
            Self {
                max_chunks: DEFAULT_MAX_CHUNKS,
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
    }

    impl<S: LocalAttachmentStore> LocalAttachments for AttachmentServer<S> {
        /// Check the request and add the attachment, under a random ID.
        async fn start_upload(&self, request: StartUploadRequest) -> Result<StartUploadResponse> {
            let now = web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis() as u64);
            let uploader = request.verify(now)?;
            if request.chunks == 0 {
                return Err(ErrorKind::Malformed.into());
            }
            if request.chunks > self.limits.max_chunks {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let token: [u8; TOKEN_LENGTH] = random();
            let attachment = StoredAttachment {
                id: random(),
                uploader,
                chunks: request.chunks,
                token_hash: Sha256::digest(token).into(),
            };
            let id = attachment.id;
            // 128 random bits do not collide, but a store that says so is believed.
            if !self.store.add_attachment(attachment).await? {
                return Err(ErrorKind::Server.into());
            }
            Ok(StartUploadResponse {
                id: Bytes::copy_from_slice(&id),
                upload_token: Bytes::copy_from_slice(&token),
            })
        }

        /// Store a chunk, if the upload token is the attachment's.
        async fn put_chunk(&self, request: PutChunkRequest) -> Result<PutChunkResponse> {
            if request.data.len() > MAX_CHUNK_SIZE {
                return Err(ErrorKind::LimitExceeded.into());
            }
            let attachment = self.uploading(&request.id, &request.upload_token).await?;
            if request.index >= attachment.chunks {
                return Err(ErrorKind::Malformed.into());
            }
            self.store
                .put_chunk(&attachment.id, request.index, request.data)
                .await?;
            Ok(PutChunkResponse {})
        }

        /// A chunk, as uploaded, or that it is not uploaded yet.
        async fn get_chunk(&self, request: GetChunkRequest) -> Result<GetChunkResponse> {
            let attachment = self.attachment(&request.id).await?;
            if request.index >= attachment.chunks {
                return Err(ErrorKind::Malformed.into());
            }
            Ok(
                match self.store.chunk(&attachment.id, request.index).await? {
                    Some(data) => GetChunkResponse {
                        data,
                        uploaded: true,
                    },
                    None => GetChunkResponse::default(),
                },
            )
        }

        /// Delete the attachment, if the upload token is its.
        async fn cancel_upload(
            &self,
            request: CancelUploadRequest,
        ) -> Result<CancelUploadResponse> {
            let attachment = self.uploading(&request.id, &request.upload_token).await?;
            self.store.delete_attachment(&attachment.id).await?;
            Ok(CancelUploadResponse {})
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
                .limits(AttachmentLimits { max_chunks: 2 })
                .build();
            let alice = XEdDSAPrivateKey::generate();
            // Too many chunks, or none.
            for (chunks, kind) in [(3, ErrorKind::LimitExceeded), (0, ErrorKind::Malformed)] {
                let request = StartUploadRequest::sign(&alice, chunks, now());
                assert_eq!(server.start_upload(request).await.unwrap_err().kind(), kind);
            }
            let started = server
                .start_upload(StartUploadRequest::sign(&alice, 2, now()))
                .await
                .unwrap();
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
            // Not uploaded yet, or never: no such chunk.
            assert!(!server.get_chunk(get(0)).await.unwrap().uploaded);
            assert_eq!(
                server.get_chunk(get(2)).await.unwrap_err().kind(),
                ErrorKind::Malformed
            );

            // Cancelled, only with the upload token, it is gone.
            let cancel = |upload_token: &Bytes| CancelUploadRequest {
                id: started.id.clone(),
                upload_token: upload_token.clone(),
            };
            assert_eq!(
                server
                    .cancel_upload(cancel(&wrong))
                    .await
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSignature
            );
            server
                .cancel_upload(cancel(&started.upload_token))
                .await
                .unwrap();
            assert_eq!(
                server.get_chunk(get(1)).await.unwrap_err().kind(),
                ErrorKind::NotFound
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MAX_CLOCK_SKEW, error::ErrorKind};

    #[test]
    fn sign_and_verify() {
        let alice = XEdDSAPrivateKey::generate();
        let request = StartUploadRequest::sign(&alice, 3, 1_000_000);
        assert_eq!(
            request.verify(1_000_000).unwrap(),
            alice.compute_public_key().to_bytes()
        );
        assert_eq!(
            request
                .verify(1_000_000 + MAX_CLOCK_SKEW + 1)
                .unwrap_err()
                .kind(),
            ErrorKind::StaleTimestamp
        );
        // The number of chunks is signed too.
        let mut changed = request.clone();
        changed.chunks = 4;
        assert_eq!(
            changed.verify(1_000_000).unwrap_err().kind(),
            ErrorKind::InvalidSignature
        );
    }
}
