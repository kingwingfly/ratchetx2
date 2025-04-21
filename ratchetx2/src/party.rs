//! The party who participates in the E2EE chat.

use crate::error::{Error, Result};
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

use crate::{Ratchetx2, key::MessageKey};

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
///
/// # #[tokio::main]
/// # async fn main() {
/// let shared_keys = SharedKeys {
///     secret_key: [0; 32],
///     header_key_alice: [1; 32],
///     header_key_bob: [2; 32],
/// };
/// let (a, b) = ChannelTransport::new();
/// let bob = shared_keys.bob();
/// let alice = shared_keys.alice(bob.public_key());
/// let mut alice = Party::new(alice, a);
/// let mut bob = Party::new(bob, b);
/// alice.send(b"hello world", b"").await.unwrap();
/// assert_eq!(bob.recv(b"").await.unwrap(), b"hello world");
/// alice.send(b"hello Bob", b"").await.unwrap();
/// assert_eq!(bob.recv(b"").await.unwrap(), b"hello Bob");
/// bob.send(b"hello Alice", b"").await.unwrap();
/// assert_eq!(alice.recv(b"").await.unwrap(), b"hello Alice");
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
}

impl<T: Transport> Party<T> {
    /// New a party.
    pub fn new(ratchetx2: Ratchetx2, transport: T) -> Self {
        Self {
            ratchetx2,
            transport,
            skipped_mk: HashMap::new(),
            pn: 0,
            ns: 0,
            nr: 0,
        }
    }

    /// Send a message.
    /// # Args
    /// - content: the bytes to send, not encrypted
    /// - aad: additional authenticated data
    pub async fn send(&mut self, content: &[u8], aad: &[u8]) -> Result<()> {
        let header = Header {
            public_key: self.ratchetx2.public_key(),
            pn: self.pn,
            n: self.ns,
        };
        let header = bincode::encode_to_vec(&header, config::standard()).unwrap();
        let header_key = self.ratchetx2.header_key_s();
        let enc_header = encrypt(header_key, &[b"Header"], aad, &header)?;

        let message_key = self.ratchetx2.step_msgs();
        let enc_content = encrypt(message_key, &[b"Content"], aad, content)?;

        self.transport
            .send(EncryptedMessage {
                enc_header,
                enc_content,
            })
            .await?;

        self.ns += 1;
        Ok(())
    }

    /// Receive a messgae.
    /// # Args
    /// - aad: additional authenticated data
    ///
    /// Returns decrypted bytes.
    pub async fn recv(&mut self, aad: &[u8]) -> Result<Vec<u8>> {
        let encrypted_message = self.transport.recv().await?;
        for header_key in self
            .skipped_mk
            .keys()
            .map(|(k, _)| *k)
            .collect::<HashSet<_>>()
            .into_iter()
        {
            if let Ok(header) =
                decrypt(header_key, &[b"Header"], aad, &encrypted_message.enc_header)
            {
                let (header, _): (Header, _) =
                    bincode::decode_from_slice(&header, config::standard())
                        .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
                match self.skipped_mk.remove(&(header_key, header.n)) {
                    Some(message_key) => {
                        return Ok(decrypt(
                            message_key,
                            &[b"Content"],
                            aad,
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
            aad,
            &encrypted_message.enc_header,
        ) {
            let (header, _): (Header, _) = bincode::decode_from_slice(&header, config::standard())
                .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
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
                aad,
                &encrypted_message.enc_content,
            )?);
        }
        if let Ok(header) = decrypt(
            self.ratchetx2.next_header_key_r(),
            &[b"Header"],
            aad,
            &encrypted_message.enc_header,
        ) {
            let (header, _): (Header, _) = bincode::decode_from_slice(&header, config::standard())
                .map_err(|_| Error::Failed("Recv: deserialize error.".to_string()))?;
            while self.nr < header.pn {
                let messgage_key = self.ratchetx2.step_msgr();
                self.skipped_mk
                    .insert((self.ratchetx2.header_key_r(), self.nr), messgage_key);
                self.nr += 1;
            }
            self.ratchetx2.step_dh_root(&header.public_key);
            self.ratchetx2.step_dh_root(&header.public_key);
            self.pn = self.ns; // about to = other.nr
            self.ns = 0;
            self.nr = 0;
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
                aad,
                &encrypted_message.enc_content,
            )?);
        }
        Err(Error::Failed("Recv: cannot decrypt.".to_string()))
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
        nonce_bytes[8..].copy_from_slice(&bytes);

        self.0 += 1; // advance the counter
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
