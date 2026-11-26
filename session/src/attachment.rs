//! Attachments: files too large for a message. They go encrypted to the attachment service, in
//! chunks, and a message carries their ID and key; see `protocol::attachment`.
//!
//! Each attachment has a random key of its own. Its plaintext is cut into chunks of
//! [`CHUNK_SIZE`] bytes, the last one shorter or empty, and each is sealed with AES-256-GCM under
//! a nonce holding its index and whether it is the last, as in the STREAM construction: chunks
//! cannot be reordered, nor an attachment cut short, without one failing to decrypt. A key seals
//! one attachment only, so no nonce repeats under it.
//!
//! An attachment can be downloaded while it is uploaded, so its ID and key can go to the
//! recipients as soon as the upload starts: [`download_chunk`] tells a chunk not uploaded yet
//! from an attachment that is gone.
//!
//! Its upload token, which the service gives the uploader alone, uploads it, and is no use once
//! it is up. Its delete token, which [`delete_token`] derives from its key, deletes it from the
//! service, at any time, for the uploader or any recipient alike, with [`delete`]: holding it
//! shows only that one knew the key, as every peer of the chat does.

use std::collections::HashMap;
use std::sync::Mutex;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, AeadCore, Payload, array::typenum::Unsigned},
};
use bytes::Bytes;
use hkdf::Hkdf;
use protocol::attachment::{
    DeleteAttachmentRequest, GetChunkRequest, ID_LENGTH, LocalAttachments, MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE, PutChunkRequest, TOKEN_LENGTH,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{ErrorKind, Result};

/// Length of the tag each chunk carries.
const TAG_LENGTH: usize = <Aes256Gcm as AeadCore>::TagSize::USIZE;
/// Length of a nonce.
const NONCE_LENGTH: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;
/// Plaintext bytes in every chunk but the last: as many as fit, with the tag, in the largest
/// chunk the service takes.
pub const CHUNK_SIZE: usize = MAX_CHUNK_SIZE - TAG_LENGTH;
/// Length of an attachment's key.
pub const KEY_LENGTH: usize = 32;
/// Domain-separation prefix for attachment chunk associated data (`b"attachment.v2\0" || id`).
const ASSOCIATED_DATA_PREFIX: &[u8; 14] = b"attachment.v2\0";
/// Length of the stack-allocated chunk AAD: `b"attachment.v2\0"` (14) || `id` (16) = 30 bytes.
const ASSOCIATED_DATA_LENGTH: usize = ASSOCIATED_DATA_PREFIX.len() + ID_LENGTH;

/// Stack-allocated chunk associated data binding the domain separator and attachment `id`:
/// `b"attachment.v2\0" || id`.
fn chunk_aad(id: &[u8; ID_LENGTH]) -> [u8; ASSOCIATED_DATA_LENGTH] {
    let mut aad = [0u8; ASSOCIATED_DATA_LENGTH];
    aad[..ASSOCIATED_DATA_PREFIX.len()].copy_from_slice(ASSOCIATED_DATA_PREFIX);
    aad[ASSOCIATED_DATA_PREFIX.len()..].copy_from_slice(id);
    aad
}

/// An attachment's key, zeroized on drop.
pub type Key = Zeroizing<[u8; KEY_LENGTH]>;

/// An attachment's upload or delete token, zeroized on drop.
pub type Token = Zeroizing<[u8; TOKEN_LENGTH]>;

/// Number of chunks of an attachment of `size` plaintext bytes: at least one, as an empty file
/// is one empty chunk.
pub fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE as u64).max(1)
}

/// Chunk `index` of attachment `id`, encrypted under `key`; `last` if it is the last chunk.
pub fn encrypt_chunk(
    key: &[u8; KEY_LENGTH],
    id: &[u8; ID_LENGTH],
    index: u32,
    last: bool,
    plaintext: &[u8],
) -> Vec<u8> {
    let aad = chunk_aad(id);
    Aes256Gcm::new(key.into())
        .encrypt(
            &nonce(index, last).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("AES-GCM encrypts any chunk that fits in memory")
}

/// The plaintext of chunk `index` of attachment `id`, encrypted under `key`; `last` if it is the
/// last chunk.
///
/// Fails with [`ErrorKind::Undecryptable`] if it is not that chunk of attachment `id` under `key`.
pub fn decrypt_chunk(
    key: &[u8; KEY_LENGTH],
    id: &[u8; ID_LENGTH],
    index: u32,
    last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let aad = chunk_aad(id);
    Aes256Gcm::new(key.into())
        .decrypt(
            &nonce(index, last).into(),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ErrorKind::Undecryptable.into())
}

/// The nonce of chunk `index`: zeros, the index (big-endian), then 1 for the last chunk, else 0.
fn nonce(index: u32, last: bool) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0; NONCE_LENGTH];
    nonce[NONCE_LENGTH - 5..NONCE_LENGTH - 1].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_LENGTH - 1] = u8::from(last);
    nonce
}

/// Per-upload nonce-reuse guard state tracking sealed chunk digests and monotonic watermarks.
#[derive(Default)]
pub(crate) struct SealedChunks {
    /// Chunks strictly below this index were already encrypted in an earlier run and must not
    /// be re-encrypted under this handle unless their persisted plaintext digest matches.
    resumed_before: u32,
    /// Monotonic high-water mark (`highest_sealed_index + 1`): encrypting any unrecorded index
    /// `< sealed_through` is refused so out-of-order/sparse gaps can never be back-filled with a
    /// reused nonce after a restart.
    sealed_through: u32,
    /// SHA-256 digest of the plaintext sealed for each chunk index encrypted on this handle (or
    /// restored via [`Upload::resume_with_digests`]).
    digests: HashMap<u32, [u8; 32]>,
}

/// An attachment being uploaded, from [`Client::start_upload`](crate::Client::start_upload):
/// its ID and key, which its recipients need, and its upload token, which only this client has.
///
/// Both its [`key`](Self::key) and [`token`](Self::token) are zeroized on drop. It tracks every
/// chunk index encrypted on this handle (and any resume watermark passed to
/// [`Upload::resume_from`]) so encrypting the same chunk index twice with different plaintext
/// fails with [`ErrorKind::NonceReuse`] rather than leaking the AES-GCM key.
///
/// To go on after a restart, keep its ID, token, key, number of chunks, and the number of chunks
/// already encrypted, and pass them to [`Upload::resume_from`] (or [`Upload::resume`] after
/// verifying the file prefix hash).
pub struct Upload {
    pub(crate) id: [u8; ID_LENGTH],
    pub(crate) token: Token,
    pub(crate) key: Key,
    pub(crate) chunks: u32,
    pub(crate) expires: Option<u64>,
    pub(crate) sealed: Mutex<SealedChunks>,
}

impl Upload {
    /// Construct a fresh upload handle starting at chunk 0.
    pub(crate) fn new(
        id: [u8; ID_LENGTH],
        token: Token,
        key: Key,
        chunks: u32,
        expires: Option<u64>,
    ) -> Self {
        Self {
            id,
            token,
            key,
            chunks,
            expires,
            sealed: Mutex::new(SealedChunks::default()),
        }
    }

    /// An upload started earlier, from its [ID](Self::id), [token](Self::token),
    /// [key](Self::key) and number of [chunks](Self::chunks), to go on with.
    ///
    /// Prefer [`Upload::resume_from`] (or [`Upload::resume_with_digests`]) whenever the caller
    /// knows how many leading chunks were already encrypted before restarting, so any accidental
    /// re-encryption of an earlier chunk is rejected with [`ErrorKind::NonceReuse`].
    pub fn resume(id: [u8; ID_LENGTH], token: impl Into<Token>, key: Key, chunks: u32) -> Self {
        Self::resume_from(id, token, key, chunks, 0)
    }

    /// An upload started earlier, refusing to encrypt any chunk index `< sealed_chunks` (and any
    /// unrecorded out-of-order index below the highest sealed index on this handle) so a resumed
    /// upload can never reuse an AES-GCM nonce across a restart.
    pub fn resume_from(
        id: [u8; ID_LENGTH],
        token: impl Into<Token>,
        key: Key,
        chunks: u32,
        sealed_chunks: u32,
    ) -> Self {
        Self::resume_with_digests(id, token, key, chunks, sealed_chunks, HashMap::new())
    }

    /// An upload started earlier with persisted chunk plaintext SHA-256 `digests` (allowing
    /// idempotent retries of already-sealed chunks only when byte-identical while rejecting any
    /// unrecorded index `< sealed_chunks` with [`ErrorKind::NonceReuse`]).
    pub fn resume_with_digests(
        id: [u8; ID_LENGTH],
        token: impl Into<Token>,
        key: Key,
        chunks: u32,
        sealed_chunks: u32,
        digests: HashMap<u32, [u8; 32]>,
    ) -> Self {
        let highest = digests
            .keys()
            .copied()
            .max()
            .map_or(0, |idx| idx.saturating_add(1));
        let sealed_through = sealed_chunks.max(highest);
        Self {
            id,
            token: token.into(),
            key,
            chunks,
            expires: None,
            sealed: Mutex::new(SealedChunks {
                resumed_before: sealed_chunks,
                sealed_through,
                digests,
            }),
        }
    }

    /// High-water mark (`highest_sealed_index + 1`) of chunks sealed by or before this handle.
    pub fn sealed_chunks(&self) -> u32 {
        self.sealed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sealed_through
    }

    /// When the server deletes the attachment, in milliseconds since the Unix epoch, after which
    /// the [token](Self::token) is no use, if it said as the upload started.
    pub fn expires(&self) -> Option<u64> {
        self.expires
    }

    /// The attachment's ID, which downloading it takes.
    pub fn id(&self) -> &[u8; ID_LENGTH] {
        &self.id
    }

    /// The attachment's key, which decrypting it takes.
    pub fn key(&self) -> &[u8; KEY_LENGTH] {
        &self.key
    }

    /// The upload token, which uploading the chunks takes: keep it secret.
    pub fn token(&self) -> &[u8; TOKEN_LENGTH] {
        &self.token
    }

    /// Number of chunks.
    pub fn chunks(&self) -> u32 {
        self.chunks
    }

    /// Encrypt chunk `index` after verifying:
    /// - `index < chunks` (else [`ErrorKind::InvalidArgument`]),
    /// - `plaintext.len() <= CHUNK_SIZE` (else [`ErrorKind::LimitExceeded`]),
    /// - `plaintext.len() == CHUNK_SIZE` for every non-last chunk (`index + 1 < chunks`, else
    ///   [`ErrorKind::InvalidArgument`]),
    /// - `index` is neither below the resumed sealed-chunk floor nor an unrecorded index below an
    ///   already-sealed higher chunk index, nor previously encrypted with different plaintext
    ///   (else [`ErrorKind::NonceReuse`]).
    ///
    /// Re-encrypting the same `index` with byte-identical `plaintext` (e.g. an idempotent retry)
    /// is allowed because AES-GCM with the same key, nonce, and plaintext produces the exact same
    /// ciphertext. Encrypting `index` with different data fails with [`ErrorKind::NonceReuse`].
    pub fn try_encrypt(&self, index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        if index >= self.chunks {
            return Err(ErrorKind::InvalidArgument.into());
        }
        if plaintext.len() > CHUNK_SIZE {
            return Err(ErrorKind::LimitExceeded.into());
        }
        let last = index + 1 == self.chunks;
        if !last && plaintext.len() != CHUNK_SIZE {
            return Err(ErrorKind::InvalidArgument.into());
        }
        let digest: [u8; 32] = Sha256::digest(plaintext).into();
        let mut sealed = self
            .sealed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(previous) = sealed.digests.get(&index) {
            if *previous != digest {
                return Err(ErrorKind::NonceReuse.into());
            }
        } else {
            if index < sealed.resumed_before || index < sealed.sealed_through {
                return Err(ErrorKind::NonceReuse.into());
            }
            sealed.digests.insert(index, digest);
            sealed.sealed_through = index.saturating_add(1);
        }
        drop(sealed);
        Ok(encrypt_chunk(&self.key, &self.id, index, last, plaintext))
    }

    /// Chunk `index`, encrypted: `plaintext` is its part of the file, [`CHUNK_SIZE`] bytes from
    /// `index * CHUNK_SIZE`, or what is left for the last chunk.
    ///
    /// Panics if [`try_encrypt`](Self::try_encrypt) refuses the chunk (e.g. nonce reuse with
    /// different plaintext or out-of-range index). Prefer [`try_encrypt`](Self::try_encrypt) for
    /// fallible error handling.
    pub fn encrypt(&self, index: u32, plaintext: &[u8]) -> Vec<u8> {
        self.try_encrypt(index, plaintext)
            .expect("refused attachment chunk encryption (nonce reuse or invalid index)")
    }

    /// Upload chunk `index`, as [encrypted](Self::try_encrypt), or upload it again, e.g. after a
    /// failure.
    ///
    /// Fails with [`ErrorKind::NotFound`] once the attachment is gone: expired, or deleted, e.g.
    /// by a recipient who does not want it, so that the rest need not go up.
    pub async fn put(
        &self,
        attachments: &impl LocalAttachments,
        index: u32,
        ciphertext: &[u8],
    ) -> Result<()> {
        attachments
            .put_chunk(PutChunkRequest {
                id: Bytes::copy_from_slice(&self.id),
                upload_token: Bytes::copy_from_slice(self.token.as_slice()),
                index,
                data: Bytes::copy_from_slice(ciphertext),
            })
            .await?;
        Ok(())
    }

    /// Cancel the upload: the attachment and its chunks go from the service, and its recipients
    /// find it gone.
    pub async fn cancel(&self, attachments: &impl LocalAttachments) -> Result<()> {
        attachments
            .delete_attachment(DeleteAttachmentRequest {
                id: Bytes::copy_from_slice(&self.id),
                token: Bytes::copy_from_slice(self.token.as_slice()),
            })
            .await?;
        Ok(())
    }
}

impl std::fmt::Debug for Upload {
    /// Shows no key or token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upload")
            .field("id", &self.id)
            .field("chunks", &self.chunks)
            .finish_non_exhaustive()
    }
}

/// Chunk `index` of the attachment `id`, as uploaded: still encrypted, for [`decrypt_chunk`].
/// `None` if it is not uploaded yet, so try again later.
///
/// Fails with [`ErrorKind::NotFound`] if the attachment is gone: expired, or cancelled.
pub async fn download_chunk(
    attachments: &impl LocalAttachments,
    id: &[u8; ID_LENGTH],
    index: u32,
) -> Result<Option<Vec<u8>>> {
    let response = attachments
        .get_chunk(GetChunkRequest {
            id: Bytes::copy_from_slice(id),
            index,
        })
        .await?;
    if !response.uploaded {
        return Ok(None);
    }
    if response.data.len() < MIN_CHUNK_SIZE || response.data.len() > MAX_CHUNK_SIZE {
        return Err(ErrorKind::InvalidResponse.into());
    }
    Ok(Some(response.data.to_vec()))
}

/// The delete token of the attachment whose key is `key`, which the uploader and its recipients
/// alike derive: HKDF-SHA256 of the key, with no salt, and `"attachment.v1/delete"` as info.
pub fn delete_token(key: &[u8; KEY_LENGTH]) -> Token {
    let mut token = Zeroizing::new([0; TOKEN_LENGTH]);
    Hkdf::<Sha256>::new(None, key)
        .expand(b"attachment.v1/delete", token.as_mut_slice())
        .expect("16 bytes are a valid HKDF-SHA256 output length");
    token
}

/// SHA-256 of the delete token of the attachment whose key is `key`, which its upload's start
/// gives the service.
pub(crate) fn delete_hash(key: &[u8; KEY_LENGTH]) -> [u8; 32] {
    let token = delete_token(key);
    Sha256::digest(token.as_slice()).into()
}

/// Delete the attachment `id`, whose key is `key`, from the service, uploaded or not: it and its
/// chunks go, and its upload stops. Its uploader or any recipient may: a recipient that does not
/// want it spares the uploader the rest of the upload.
///
/// Fails with [`ErrorKind::NotFound`] if it is gone already: expired, or deleted.
pub async fn delete(
    attachments: &impl LocalAttachments,
    id: &[u8; ID_LENGTH],
    key: &[u8; KEY_LENGTH],
) -> Result<()> {
    let token = delete_token(key);
    attachments
        .delete_attachment(DeleteAttachmentRequest {
            id: Bytes::copy_from_slice(id),
            token: Bytes::copy_from_slice(token.as_slice()),
        })
        .await?;
    Ok(())
}

/// A new random key, returning an error if the OS RNG fails.
pub(crate) fn try_generate_key() -> Result<Key> {
    let mut key = Zeroizing::new([0; KEY_LENGTH]);
    getrandom::fill(key.as_mut_slice()).map_err(|_| ErrorKind::Protocol)?;
    Ok(key)
}

#[cfg(test)]
fn generate_key() -> Key {
    try_generate_key().expect("the system random number generator failed")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chunks_decrypt_only_in_place() {
        let key = generate_key();
        let id = [0x42; ID_LENGTH];
        let other_id = [0x43; ID_LENGTH];
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64 + 1), 2);
        assert_eq!(chunk_aad(&id).len(), 30);

        let first = encrypt_chunk(&key, &id, 0, false, b"first");
        let last = encrypt_chunk(&key, &id, 1, true, b"last");
        assert_eq!(last.len(), b"last".len() + TAG_LENGTH);
        assert_eq!(
            decrypt_chunk(&key, &id, 0, false, &first).unwrap(),
            b"first"
        );
        assert_eq!(decrypt_chunk(&key, &id, 1, true, &last).unwrap(), b"last");
        // Elsewhere, as the last when it is not (the attachment cut short), under another
        // attachment ID, or under another key, a chunk does not decrypt.
        for (index, is_last, chunk) in [(1, false, &first), (0, true, &first), (0, false, &last)] {
            let error = decrypt_chunk(&key, &id, index, is_last, chunk).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Undecryptable);
        }
        assert_eq!(
            decrypt_chunk(&key, &other_id, 0, false, &first)
                .unwrap_err()
                .kind(),
            ErrorKind::Undecryptable
        );
        assert_eq!(
            decrypt_chunk(&generate_key(), &id, 0, false, &first)
                .unwrap_err()
                .kind(),
            ErrorKind::Undecryptable
        );
    }

    #[test]
    fn upload_guards_against_nonce_reuse_and_resumed_floor() {
        let key = generate_key();
        let full_chunk = vec![0x11; CHUNK_SIZE];
        let mut diff_chunk = full_chunk.clone();
        diff_chunk[0] ^= 0xFF;

        let upload = Upload::new(
            [1; ID_LENGTH],
            Zeroizing::new([2; TOKEN_LENGTH]),
            key,
            3,
            None,
        );
        // Short non-last chunk, oversized chunk, and out-of-range index are distinct from NonceReuse.
        assert_eq!(
            upload.try_encrypt(0, b"too-short").unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            upload
                .try_encrypt(0, &vec![0u8; CHUNK_SIZE + 1])
                .unwrap_err()
                .kind(),
            ErrorKind::LimitExceeded
        );
        assert_eq!(
            upload.try_encrypt(3, b"oob").unwrap_err().kind(),
            ErrorKind::InvalidArgument
        );

        let c0 = upload.try_encrypt(0, &full_chunk).unwrap();
        assert_eq!(upload.sealed_chunks(), 1);
        // Idempotent retry with identical plaintext produces the exact same ciphertext.
        let c0_retry = upload.try_encrypt(0, &full_chunk).unwrap();
        assert_eq!(c0, c0_retry);
        // Encrypting the same chunk index with different plaintext is rejected!
        let err = upload.try_encrypt(0, &diff_chunk).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NonceReuse);

        // Skipping index 1 to seal index 2 permanently closes unrecorded gap 1 against nonce reuse.
        let _c2 = upload.try_encrypt(2, b"chunk-two").unwrap();
        assert_eq!(upload.sealed_chunks(), 3);
        assert_eq!(
            upload.try_encrypt(1, &full_chunk).unwrap_err().kind(),
            ErrorKind::NonceReuse
        );

        // Resumed upload refuses any chunk below `sealed_chunks`.
        let resumed =
            Upload::resume_from(*upload.id(), *upload.token(), Key::new(*upload.key()), 3, 2);
        assert_eq!(
            resumed.try_encrypt(0, &full_chunk).unwrap_err().kind(),
            ErrorKind::NonceReuse
        );
        assert_eq!(
            resumed.try_encrypt(1, &full_chunk).unwrap_err().kind(),
            ErrorKind::NonceReuse
        );
        let c2 = resumed.try_encrypt(2, b"chunk-two").unwrap();
        assert_eq!(
            decrypt_chunk(resumed.key(), resumed.id(), 2, true, &c2).unwrap(),
            b"chunk-two"
        );
    }

    #[test]
    #[should_panic(expected = "refused attachment chunk encryption")]
    fn legacy_encrypt_fails_closed_on_different_plaintext() {
        let upload = Upload::new(
            [1; ID_LENGTH],
            Zeroizing::new([2; TOKEN_LENGTH]),
            generate_key(),
            1,
            None,
        );
        let _ = upload.encrypt(0, b"original");
        let _ = upload.encrypt(0, b"tampered");
    }

    #[tokio::test]
    async fn download_chunk_rejects_oversized_or_truncated_response() {
        struct BadSizeAttachments(Vec<u8>);
        impl LocalAttachments for BadSizeAttachments {
            async fn start_upload(
                &self,
                _: protocol::attachment::StartUploadRequest,
            ) -> protocol::Result<protocol::attachment::StartUploadResponse> {
                unreachable!()
            }
            async fn put_chunk(
                &self,
                _: PutChunkRequest,
            ) -> protocol::Result<protocol::attachment::PutChunkResponse> {
                unreachable!()
            }
            async fn get_chunk(
                &self,
                _: GetChunkRequest,
            ) -> protocol::Result<protocol::attachment::GetChunkResponse> {
                Ok(protocol::attachment::GetChunkResponse {
                    data: Bytes::from(self.0.clone()),
                    uploaded: true,
                })
            }
            async fn delete_attachment(
                &self,
                _: DeleteAttachmentRequest,
            ) -> protocol::Result<protocol::attachment::DeleteAttachmentResponse> {
                unreachable!()
            }
        }
        assert_eq!(
            download_chunk(
                &BadSizeAttachments(vec![0; MAX_CHUNK_SIZE + 1]),
                &[1; 16],
                0
            )
            .await
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidResponse
        );
        assert_eq!(
            download_chunk(
                &BadSizeAttachments(vec![0; MIN_CHUNK_SIZE - 1]),
                &[1; 16],
                0
            )
            .await
            .unwrap_err()
            .kind(),
            ErrorKind::InvalidResponse
        );
    }
}
