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
    PutChunkRequest, TOKEN_LENGTH,
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
/// The associated data of every chunk.
const ASSOCIATED_DATA: &[u8] = b"attachment.v1";

/// An attachment's key, zeroized on drop.
pub type Key = Zeroizing<[u8; KEY_LENGTH]>;

/// An attachment's upload or delete token, zeroized on drop.
pub type Token = Zeroizing<[u8; TOKEN_LENGTH]>;

/// Number of chunks of an attachment of `size` plaintext bytes: at least one, as an empty file
/// is one empty chunk.
pub fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE as u64).max(1)
}

/// Chunk `index` of an attachment, encrypted under `key`; `last` if it is the last chunk.
pub fn encrypt_chunk(key: &[u8; KEY_LENGTH], index: u32, last: bool, plaintext: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into())
        .encrypt(
            &nonce(index, last).into(),
            Payload {
                msg: plaintext,
                aad: ASSOCIATED_DATA,
            },
        )
        .expect("AES-GCM encrypts any chunk that fits in memory")
}

/// The plaintext of chunk `index`, encrypted under `key`; `last` if it is the last chunk.
///
/// Fails with [`ErrorKind::Undecryptable`] if it is not that chunk of an attachment under `key`.
pub fn decrypt_chunk(
    key: &[u8; KEY_LENGTH],
    index: u32,
    last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    Aes256Gcm::new(key.into())
        .decrypt(
            &nonce(index, last).into(),
            Payload {
                msg: ciphertext,
                aad: ASSOCIATED_DATA,
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

/// Per-upload nonce-reuse guard state tracking sealed chunk digests and resume watermark.
#[derive(Default)]
pub(crate) struct SealedChunks {
    /// Chunks strictly below this index were already encrypted in an earlier run and must not
    /// be re-encrypted under this handle.
    resumed_before: u32,
    /// SHA-256 digest of the plaintext sealed for each chunk index encrypted on this handle.
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
    /// Prefer [`Upload::resume_from`] whenever the caller knows how many leading chunks were
    /// already encrypted before restarting, so any accidental re-encryption of an earlier chunk
    /// is rejected with [`ErrorKind::NonceReuse`].
    pub fn resume(id: [u8; ID_LENGTH], token: [u8; TOKEN_LENGTH], key: Key, chunks: u32) -> Self {
        Self::resume_from(id, Zeroizing::new(token), key, chunks, 0)
    }

    /// An upload started earlier, refusing to encrypt any chunk index `< sealed_chunks` so a
    /// resumed upload can never reuse an AES-GCM nonce across a restart.
    pub fn resume_from(
        id: [u8; ID_LENGTH],
        token: impl Into<Token>,
        key: Key,
        chunks: u32,
        sealed_chunks: u32,
    ) -> Self {
        Self {
            id,
            token: token.into(),
            key,
            chunks,
            expires: None,
            sealed: Mutex::new(SealedChunks {
                resumed_before: sealed_chunks,
                digests: HashMap::new(),
            }),
        }
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

    /// Encrypt chunk `index` after verifying it is in range (`index < chunks`), not below the
    /// resumed sealed-chunk floor, and not previously encrypted with different plaintext.
    ///
    /// Re-encrypting the same `index` with byte-identical `plaintext` (e.g. an idempotent retry)
    /// is allowed because AES-GCM with the same key, nonce, and plaintext produces the exact same
    /// ciphertext. Encrypting `index` with different data fails with [`ErrorKind::NonceReuse`].
    pub fn try_encrypt(&self, index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        if index >= self.chunks || plaintext.len() > CHUNK_SIZE {
            return Err(ErrorKind::NonceReuse.into());
        }
        let digest: [u8; 32] = Sha256::digest(plaintext).into();
        let mut sealed = self
            .sealed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if index < sealed.resumed_before {
            return Err(ErrorKind::NonceReuse.into());
        }
        if let Some(previous) = sealed.digests.get(&index) {
            if *previous != digest {
                return Err(ErrorKind::NonceReuse.into());
            }
        } else {
            sealed.digests.insert(index, digest);
        }
        drop(sealed);
        Ok(encrypt_chunk(
            &self.key,
            index,
            index + 1 == self.chunks,
            plaintext,
        ))
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
    Ok(response.uploaded.then(|| response.data.to_vec()))
}

/// The delete token of the attachment whose key is `key`, which the uploader and its recipients
/// alike derive: HKDF-SHA256 of the key, with no salt, and `"attachment.v1/delete"` as info.
pub fn delete_token(key: &[u8; KEY_LENGTH]) -> [u8; TOKEN_LENGTH] {
    let mut token = [0; TOKEN_LENGTH];
    Hkdf::<Sha256>::new(None, key)
        .expand(b"attachment.v1/delete", &mut token)
        .expect("16 bytes are a valid HKDF-SHA256 output length");
    token
}

/// SHA-256 of the delete token of the attachment whose key is `key`, which its upload's start
/// gives the service.
pub(crate) fn delete_hash(key: &[u8; KEY_LENGTH]) -> [u8; 32] {
    let token = Zeroizing::new(delete_token(key));
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
    let token = Zeroizing::new(delete_token(key));
    attachments
        .delete_attachment(DeleteAttachmentRequest {
            id: Bytes::copy_from_slice(id),
            token: Bytes::copy_from_slice(token.as_slice()),
        })
        .await?;
    Ok(())
}

/// A new random key.
pub(crate) fn generate_key() -> Key {
    let mut key = Zeroizing::new([0; KEY_LENGTH]);
    getrandom::fill(key.as_mut_slice()).expect("the system random number generator failed");
    key
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chunks_decrypt_only_in_place() {
        let key = generate_key();
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64 + 1), 2);

        let first = encrypt_chunk(&key, 0, false, b"first");
        let last = encrypt_chunk(&key, 1, true, b"last");
        assert_eq!(last.len(), b"last".len() + TAG_LENGTH);
        assert_eq!(decrypt_chunk(&key, 0, false, &first).unwrap(), b"first");
        assert_eq!(decrypt_chunk(&key, 1, true, &last).unwrap(), b"last");
        // Elsewhere, as the last when it is not (the attachment cut short), or under another
        // key, a chunk does not decrypt.
        for (index, is_last, chunk) in [(1, false, &first), (0, true, &first), (0, false, &last)] {
            let error = decrypt_chunk(&key, index, is_last, chunk).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Undecryptable);
        }
        assert!(decrypt_chunk(&generate_key(), 0, false, &first).is_err());
    }

    #[test]
    fn upload_guards_against_nonce_reuse_and_resumed_floor() {
        let key = generate_key();
        let upload = Upload::new([1; ID_LENGTH], Zeroizing::new([2; TOKEN_LENGTH]), key, 3, None);
        let c0 = upload.try_encrypt(0, b"chunk-zero").unwrap();
        // Idempotent retry with identical plaintext produces the exact same ciphertext.
        let c0_retry = upload.try_encrypt(0, b"chunk-zero").unwrap();
        assert_eq!(c0, c0_retry);
        // Encrypting the same chunk index with different plaintext is rejected!
        let err = upload.try_encrypt(0, b"DIFFERENT!").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NonceReuse);
        // Out-of-range chunk index is rejected.
        let err = upload.try_encrypt(3, b"oob").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NonceReuse);

        // Resumed upload refuses any chunk below `sealed_chunks`.
        let resumed = Upload::resume_from(
            *upload.id(),
            *upload.token(),
            Key::new(*upload.key()),
            3,
            2,
        );
        assert_eq!(
            resumed.try_encrypt(0, b"chunk-zero").unwrap_err().kind(),
            ErrorKind::NonceReuse
        );
        assert_eq!(
            resumed.try_encrypt(1, b"chunk-one").unwrap_err().kind(),
            ErrorKind::NonceReuse
        );
        let c2 = resumed.try_encrypt(2, b"chunk-two").unwrap();
        assert_eq!(
            decrypt_chunk(resumed.key(), 2, true, &c2).unwrap(),
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
            2,
            None,
        );
        let _ = upload.encrypt(0, b"original");
        let _ = upload.encrypt(0, b"tampered");
    }
}
