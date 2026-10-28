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

/// An attachment being uploaded, from [`Client::start_upload`](crate::Client::start_upload):
/// its ID and key, which its recipients need, and its upload token, which only this client has.
///
/// To go on after a restart, keep its ID, token, key and number of chunks, which
/// [`Upload::resume`] takes back, with the chunks uploaded. Encrypting a chunk again gives the
/// same ciphertext only for the same plaintext: before going on, check that the file is still the
/// same, at least as far as any chunk may have been encrypted, as another plaintext under the
/// same key and nonce would give the key away.
pub struct Upload {
    pub(crate) id: [u8; ID_LENGTH],
    pub(crate) token: [u8; TOKEN_LENGTH],
    pub(crate) key: Key,
    pub(crate) chunks: u32,
    pub(crate) expires: Option<u64>,
}

impl Upload {
    /// An upload started earlier, from its [ID](Self::id), [token](Self::token),
    /// [key](Self::key) and number of [chunks](Self::chunks), to go on with.
    pub fn resume(id: [u8; ID_LENGTH], token: [u8; TOKEN_LENGTH], key: Key, chunks: u32) -> Self {
        Self {
            id,
            token,
            key,
            chunks,
            expires: None,
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

    /// Chunk `index`, encrypted: `plaintext` is its part of the file, [`CHUNK_SIZE`] bytes from
    /// `index * CHUNK_SIZE`, or what is left for the last chunk.
    pub fn encrypt(&self, index: u32, plaintext: &[u8]) -> Vec<u8> {
        encrypt_chunk(&self.key, index, index + 1 == self.chunks, plaintext)
    }

    /// Upload chunk `index`, as [encrypted](Self::encrypt), or upload it again, e.g. after a
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
                upload_token: Bytes::copy_from_slice(&self.token),
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
                token: Bytes::copy_from_slice(&self.token),
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
    Sha256::digest(delete_token(key)).into()
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
    attachments
        .delete_attachment(DeleteAttachmentRequest {
            id: Bytes::copy_from_slice(id),
            token: Bytes::copy_from_slice(&delete_token(key)),
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
}
