//! The party who participates in the E2EE chat.

use crate::error::{Error, Result};
use crate::{Ratchetx2, key::MessageKey};
use crate::{
    key::HeaderKey,
    transport::{EncryptedMessage, Transport},
};

use std::collections::{HashMap, HashSet};

use bincode::{Decode, Encode, config};
use ring::aead::OpeningKey;
use ring::{
    aead::{AES_256_GCM, Aad, BoundKey, NONCE_LEN, Nonce, NonceSequence, SealingKey, UnboundKey},
    error::Unspecified,
    hkdf::{HKDF_SHA256, KeyType, Salt},
    hmac::{HMAC_SHA256, Key, sign, verify},
};

/// Maximum number of skipped messages allowed.
pub const SKIP_MAX: usize = 1024;

#[derive(Debug, Encode, Decode)]
struct Header {
    /// UnparsedPublicKey: AsRef<[u8]>
    public_key: Vec<u8>,
    /// Number of msg keys in revious msg chain block.
    pn: usize,
    /// Index in current msg chain block.
    n: usize,
}

/// The party who participates in the E2EE chat.
/// # Example
/// ```
/// use ratchetx2::{transport::ChannelTransport, Party, SharedKeys};
/// use ratchetx2::rand::SystemRandom;
/// use ratchetx2::agreement::{EphemeralPrivateKey, X25519};
///
/// # #[tokio::main]
/// # async fn main() {
/// let shared_keys = SharedKeys {
///     secret_key: [0; 32],
///     header_key_alice: [1; 32],
///     header_key_bob: [2; 32],
/// };
/// let bob_ratchetx2 = shared_keys.bob(EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).unwrap());
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

    /// Push a message.
    /// # Args
    /// - content: the bytes to push, not encrypted
    pub async fn push(&mut self, content: impl AsRef<[u8]>) -> Result<()> {
        let header = Header {
            public_key: self.ratchetx2.public_key(),
            pn: self.pn,
            n: self.ns,
        };
        let header = bincode::encode_to_vec(&header, config::standard()).unwrap();
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

    /// Fetch messages.
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
                        let (header, _): (Header, _) =
                            bincode::decode_from_slice(&header, config::standard()).map_err(
                                |_| Error::Failed("Recv: deserialize error.".to_string()),
                            )?;
                        match self.skipped_mk.remove(&(header_key, header.n)) {
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
                    let (header, _): (Header, _) =
                        bincode::decode_from_slice(&header, config::standard())
                            .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
                    if self.skipped_mk.len() + header.n - self.nr > SKIP_MAX {
                        return Err(Error::Failed(
                            "Recv: too many skipped messages.".to_string(),
                        ));
                    }
                    while self.nr < header.n {
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
                    let (header, _): (Header, _) =
                        bincode::decode_from_slice(&header, config::standard())
                            .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
                    if self.skipped_mk.len() + header.pn - self.nr > SKIP_MAX {
                        return Err(Error::Failed(
                            "Recv: too many skipped messages.".to_string(),
                        ));
                    }
                    while self.nr < header.pn {
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
                    if self.skipped_mk.len() + header.n - self.nr > SKIP_MAX {
                        return Err(Error::Failed(
                            "Recv: too many skipped messages.".to_string(),
                        ));
                    }
                    while self.nr < header.n {
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

struct HkdfBytes64;
impl KeyType for HkdfBytes64 {
    fn len(&self) -> usize {
        64
    }
}

#[derive(Debug)]
struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> core::result::Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[NONCE_LEN - 4..].copy_from_slice(&bytes);

        self.0 += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Hmac based key derive function. Return 2 32-byte keys.
fn hkdf32x2(key: &[u8], info: &[&[u8]]) -> core::result::Result<([u8; 32], [u8; 32]), Unspecified> {
    let salt = Salt::new(HKDF_SHA256, &[0; 32]);
    let prk = salt.extract(key);
    let okm = prk.expand(info, HkdfBytes64)?;
    let mut keys = [0; 64];
    okm.fill(&mut keys)?;
    let encryption_key = &keys[..32];
    let authentication_key = &keys[32..64];
    Ok((
        encryption_key.try_into().unwrap(),
        authentication_key.try_into().unwrap(),
    ))
}

fn encrypt(
    key: [u8; 32],
    info: &[&[u8]],
    aad: &[u8],
    content: &[u8],
) -> core::result::Result<Vec<u8>, Unspecified> {
    let (encryption_key, authentication_key) = hkdf32x2(&key, info)?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, &encryption_key)?;
    let mut sealing_key = SealingKey::new(unbound_key, CounterNonceSequence(0));
    let additional_authenticated_data = Aad::from(aad);
    let mut in_out = content.to_vec();
    sealing_key.seal_in_place_append_tag(additional_authenticated_data, &mut in_out)?;

    let hmac_key = Key::new(HMAC_SHA256, &authentication_key);
    let mut to_sign = aad.to_vec();
    to_sign.extend(in_out.clone());
    let tag = sign(&hmac_key, &to_sign);
    in_out.extend(tag.as_ref());
    Ok(in_out)
}

fn decrypt(
    key: [u8; 32],
    info: &[&[u8]],
    aad: &[u8],
    encrypted: &[u8],
) -> core::result::Result<Vec<u8>, Unspecified> {
    if encrypted.len() < 32 {
        return Err(Unspecified);
    }
    let (encryption_key, authentication_key) = hkdf32x2(&key, info)?;

    let hmac_key = Key::new(HMAC_SHA256, &authentication_key);
    let mut to_verify = aad.to_vec();
    to_verify.extend(&encrypted[..encrypted.len() - 32]);
    verify(&hmac_key, &to_verify, &encrypted[encrypted.len() - 32..])?;

    let unbound_key = UnboundKey::new(&AES_256_GCM, &encryption_key)?;
    let mut opening_key = OpeningKey::new(unbound_key, CounterNonceSequence(0));
    let mut in_out = encrypted[..encrypted.len() - 32].to_vec();
    let additional_authenticated_data = Aad::from(aad);

    Ok(opening_key
        .open_in_place(additional_authenticated_data, &mut in_out)?
        .to_vec())
}
