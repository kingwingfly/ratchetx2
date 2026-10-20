//! The party who participates in the E2EE chat.

use crate::error::{Error, Result};
use crate::transport::{EncryptedMessage, Transport};

use std::collections::{HashMap, HashSet};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message as _;
use ratchetx2::{
    Ratchetx2,
    error::CryptoError,
    key::{HeaderKey, MessageKey},
};
use sha2::Sha256;

/// Maximum number of skipped messages allowed.
pub const SKIP_MAX: usize = 1024;

#[derive(prost::Message)]
struct Header {
    /// UnparsedPublicKey: AsRef<[u8]>
    #[prost(bytes = "vec", tag = "1")]
    public_key: Vec<u8>,
    /// Number of msg keys in revious msg chain block.
    #[prost(uint64, tag = "2")]
    pn: u64,
    /// Index in current msg chain block.
    #[prost(uint64, tag = "3")]
    n: u64,
}

/// The party who participates in the E2EE chat.
/// # Example
/// ```
/// use ratchetx2::{DhPrivateKey, SharedKeys};
/// use primitives::{transport::ChannelTransport, Party};
///
/// # #[tokio::main]
/// # async fn main() {
/// let shared_keys = SharedKeys {
///     secret_key: [0; 32],
///     header_key_alice: [1; 32],
///     header_key_bob: [2; 32],
/// };
/// let bob_ratchetx2 = shared_keys.bob(DhPrivateKey::generate());
/// let alice_ratchetx2 = shared_keys.alice(&bob_ratchetx2.public_key());
/// let (a, b) = ChannelTransport::new();
/// let mut alice = Party::new(alice_ratchetx2, a, "AliceBob");
/// let mut bob = Party::new(bob_ratchetx2, b, "AliceBob");
/// alice.push("hello world").await.unwrap();
/// assert_eq!(bob.fetch().await.unwrap().remove(0).unwrap(), b"hello world");
/// alice.push("hello Bob").await.unwrap();
/// assert_eq!(bob.fetch().await.unwrap().remove(0).unwrap(), b"hello Bob");
/// bob.push("hello Alice").await.unwrap();
/// assert_eq!(alice.fetch().await.unwrap().remove(0).unwrap(), b"hello Alice");
/// # }
/// ```
#[derive(Debug)]
pub struct Party<T: Transport> {
    ratchetx2: Ratchetx2,
    transport: T,
    /// (HeaderKey, N)
    skipped_mk: HashMap<(HeaderKey, usize), MessageKey>,
    pn: usize,
    ns: usize,
    nr: usize,
    associated_data: Vec<u8>,
}

impl<T: Transport> Party<T> {
    /// New a party.
    ///
    /// # Args
    /// - associated_data: used in enryption
    pub fn new(ratchetx2: Ratchetx2, transport: T, associated_data: impl AsRef<[u8]>) -> Self {
        Self {
            ratchetx2,
            transport,
            skipped_mk: HashMap::new(),
            pn: 0,
            ns: 0,
            nr: 0,
            associated_data: associated_data.as_ref().to_vec(),
        }
    }

    /// Encrypt and push a message.
    /// # Args
    /// - content: the bytes to push, not encrypted
    pub async fn push(&mut self, content: impl AsRef<[u8]>) -> Result<()> {
        let header = Header {
            public_key: self.ratchetx2.public_key(),
            pn: self.pn as u64,
            n: self.ns as u64,
        };
        let header = header.encode_to_vec();
        let header_key = self.ratchetx2.header_key_s();
        let enc_header = encrypt(header_key, &[b"Header"], &self.associated_data, &header)?;

        let message_key = self.ratchetx2.step_msgs();
        let enc_content = encrypt(
            message_key,
            &[b"Content"],
            &self.associated_data,
            content.as_ref(),
        )?;

        self.transport
            .push(EncryptedMessage {
                enc_header,
                enc_content,
            })
            .await?;

        self.ns += 1;
        Ok(())
    }

    /// Fetch and decrypt messages.
    ///
    /// Returns decrypted bytes.
    pub async fn fetch(&mut self) -> Result<Vec<Result<Vec<u8>>>> {
        let encrypted_messages = self.transport.fetch(None).await?;
        let decrypted_messages = encrypted_messages
            .into_iter()
            .map(|encrypted_message| {
                for header_key in self
                    .skipped_mk
                    .keys()
                    .map(|(k, _)| *k)
                    .collect::<HashSet<_>>()
                    .into_iter()
                {
                    if let Ok(header) = decrypt(
                        header_key,
                        &[b"Header"],
                        &self.associated_data,
                        &encrypted_message.enc_header,
                    ) {
                        let header = Header::decode(header.as_slice())
                            .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
                        match self.skipped_mk.remove(&(header_key, header.n as usize)) {
                            Some(message_key) => {
                                return Ok(decrypt(
                                    message_key,
                                    &[b"Content"],
                                    &self.associated_data,
                                    &encrypted_message.enc_content,
                                )?);
                            }
                            None => break,
                        }
                    }
                }
                if let Ok(header) = decrypt(
                    self.ratchetx2.header_key_r(),
                    &[b"Header"],
                    &self.associated_data,
                    &encrypted_message.enc_header,
                ) {
                    let header = Header::decode(header.as_slice())
                        .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
                    let n = header.n as usize;
                    if self.skipped_mk.len() + n - self.nr > SKIP_MAX {
                        return Err(Error::Failed(
                            "Recv: too many skipped messages.".to_string(),
                        ));
                    }
                    while self.nr < n {
                        let messgage_key = self.ratchetx2.step_msgr();
                        self.skipped_mk
                            .insert((self.ratchetx2.header_key_r(), self.nr), messgage_key);
                        self.nr += 1;
                    }
                    let message_key = self.ratchetx2.step_msgr();
                    self.nr += 1;
                    return Ok(decrypt(
                        message_key,
                        &[b"Content"],
                        &self.associated_data,
                        &encrypted_message.enc_content,
                    )?);
                }
                if let Ok(header) = decrypt(
                    self.ratchetx2.next_header_key_r(),
                    &[b"Header"],
                    &self.associated_data,
                    &encrypted_message.enc_header,
                ) {
                    let header = Header::decode(header.as_slice())
                        .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
                    let (pn, n) = (header.pn as usize, header.n as usize);
                    if self.skipped_mk.len() + pn - self.nr > SKIP_MAX {
                        return Err(Error::Failed(
                            "Recv: too many skipped messages.".to_string(),
                        ));
                    }
                    while self.nr < pn {
                        let message_key = self.ratchetx2.step_msgr();
                        self.skipped_mk
                            .insert((self.ratchetx2.header_key_r(), self.nr), message_key);
                        self.nr += 1;
                    }
                    self.ratchetx2.step_dh_root(&header.public_key);
                    self.ratchetx2.step_dh_root(&header.public_key);
                    self.pn = self.ns;
                    self.ns = 0;
                    self.nr = 0;
                    if self.skipped_mk.len() + n - self.nr > SKIP_MAX {
                        return Err(Error::Failed(
                            "Recv: too many skipped messages.".to_string(),
                        ));
                    }
                    while self.nr < n {
                        let messgage_key = self.ratchetx2.step_msgr();
                        self.skipped_mk
                            .insert((self.ratchetx2.header_key_r(), self.nr), messgage_key);
                        self.nr += 1;
                    }
                    let message_key = self.ratchetx2.step_msgr();
                    self.nr += 1;
                    return Ok(decrypt(
                        message_key,
                        &[b"Content"],
                        &self.associated_data,
                        &encrypted_message.enc_content,
                    )?);
                }
                Err(Error::Failed("Recv: cannot decrypt.".to_string()))
            })
            .collect();
        Ok(decrypted_messages)
    }
}

/// Hmac based key derive function. Return 2 32-byte keys.
fn hkdf32x2(key: &[u8], info: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut keys = [0; 64];
    Hkdf::<Sha256>::new(Some(&[0; 32]), key)
        .expand_multi_info(info, &mut keys)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let encryption_key = &keys[..32];
    let authentication_key = &keys[32..64];
    (
        encryption_key.try_into().unwrap(),
        authentication_key.try_into().unwrap(),
    )
}

/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;
/// HMAC-SHA256 tag length.
const TAG_LEN: usize = 32;

/// Encrypt to `nonce || AES-256-GCM ciphertext || HMAC-SHA256(aad || nonce || ciphertext)`.
///
/// A header key encrypts every header of its chain, so each call draws a fresh random nonce.
fn encrypt(
    key: [u8; 32],
    info: &[&[u8]],
    aad: &[u8],
    content: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    let (encryption_key, authentication_key) = hkdf32x2(&key, info);

    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError)?;
    let mut out = nonce.to_vec();
    out.extend(
        Aes256Gcm::new(&encryption_key.into())
            .encrypt(&nonce.into(), Payload { msg: content, aad })
            .map_err(|_| CryptoError)?,
    );

    let mut hmac = Hmac::<Sha256>::new_from_slice(&authentication_key).unwrap();
    hmac.update(aad);
    hmac.update(&out);
    out.extend(hmac.finalize().into_bytes());
    Ok(out)
}

fn decrypt(
    key: [u8; 32],
    info: &[&[u8]],
    aad: &[u8],
    encrypted: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let (encryption_key, authentication_key) = hkdf32x2(&key, info);
    let (nonce_and_ciphertext, tag) = encrypted.split_at(encrypted.len() - TAG_LEN);

    let mut hmac = Hmac::<Sha256>::new_from_slice(&authentication_key).unwrap();
    hmac.update(aad);
    hmac.update(nonce_and_ciphertext);
    hmac.verify_slice(tag).map_err(|_| CryptoError)?;

    let (nonce, ciphertext) = nonce_and_ciphertext.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
    Aes256Gcm::new(&encryption_key.into())
        .decrypt(
            &nonce.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn reused_header_key_gets_fresh_nonces() {
        let header_key = [7; 32];
        let a = encrypt(header_key, &[b"Header"], b"ad", b"same header").unwrap();
        let b = encrypt(header_key, &[b"Header"], b"ad", b"same header").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
        assert_eq!(
            decrypt(header_key, &[b"Header"], b"ad", &a).unwrap(),
            b"same header"
        );
        assert_eq!(
            decrypt(header_key, &[b"Header"], b"ad", &b).unwrap(),
            b"same header"
        );

        let mut tampered = a.clone();
        tampered[0] ^= 1;
        assert!(decrypt(header_key, &[b"Header"], b"ad", &tampered).is_err());
        assert!(decrypt(header_key, &[b"Header"], b"other ad", &a).is_err());
        assert!(
            decrypt(
                header_key,
                &[b"Header"],
                b"ad",
                &a[..NONCE_LEN + TAG_LEN - 1]
            )
            .is_err()
        );
    }
}
