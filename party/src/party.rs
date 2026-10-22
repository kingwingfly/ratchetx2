//! The party who participates in the E2EE chat.

use crate::error::{Error, ErrorKind, Result};
use crate::proto::{EncryptedMessage, Header};

use std::collections::{HashMap, HashSet};
use std::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit, KeySizeUser,
    aead::{Aead, AeadCore, Payload, array::typenum::Unsigned},
};
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, digest::OutputSizeUser};
use prost::Message as _;
use ratchetx2::{
    Ratchet,
    error::CryptoError,
    key::{HeaderKey, KEY_LENGTH, MessageKey},
};
use sha2::Sha256;

/// Maximum number of skipped messages allowed.
pub const SKIP_MAX: u64 = 1024;

/// The party who participates in the E2EE chat: encrypts and decrypts messages, without I/O.
/// See the example in the [crate docs](crate).
pub struct Party {
    ratchet: Ratchet,
    /// (HeaderKey, message number)
    skipped_message_keys: HashMap<(HeaderKey, u64), MessageKey>,
    /// Number of messages in the previous sending chain.
    previous_chain_length: u64,
    /// Number of the next message to send in the current sending chain.
    message_number_sender: u64,
    /// Number of the next message expected in the current receiving chain.
    message_number_receiver: u64,
    associated_data: Vec<u8>,
}

impl fmt::Debug for Party {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Party")
            .field("previous_chain_length", &self.previous_chain_length)
            .field("message_number_sender", &self.message_number_sender)
            .field("message_number_receiver", &self.message_number_receiver)
            .field("skipped", &self.skipped_message_keys.len())
            .finish_non_exhaustive()
    }
}

/// Message keys skipped over while receiving, keyed like [`Party`]'s `skipped_message_keys`.
type SkippedKeys = Vec<((HeaderKey, u64), MessageKey)>;

impl Party {
    /// New a party.
    ///
    /// # Args
    /// - associated_data: used in encryption
    pub fn new(ratchet: Ratchet, associated_data: impl AsRef<[u8]>) -> Self {
        Self {
            ratchet,
            skipped_message_keys: HashMap::new(),
            previous_chain_length: 0,
            message_number_sender: 0,
            message_number_receiver: 0,
            associated_data: associated_data.as_ref().to_vec(),
        }
    }

    /// Encrypt a message.
    ///
    /// Bob has no sending chain until he has decrypted Alice's first message;
    /// until then this returns an error.
    pub fn encrypt(&mut self, content: &[u8]) -> Result<EncryptedMessage> {
        let header_key = self
            .ratchet
            .header_key_sender()
            .ok_or(ErrorKind::NoSendingChain)?;
        let header = Header {
            public_key: Bytes::from(self.ratchet.public_key()),
            previous_chain_length: self.previous_chain_length,
            message_number: self.message_number_sender,
        };
        let header = encrypt(
            header_key,
            &[b"Header"],
            &self.associated_data,
            &header.encode_to_vec(),
        )?;
        let message_key = self
            .ratchet
            .step_message_ratchet_sender()
            .ok_or(ErrorKind::NoSendingChain)?;
        self.message_number_sender += 1;
        let content = encrypt(message_key, &[b"Content"], &self.associated_data, content)?;
        Ok(EncryptedMessage {
            header: Bytes::from(header),
            content: Bytes::from(content),
        })
    }

    /// Decrypt a message. The state only changes if the content decrypts.
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        if let Some(content) = self.receive_skipped(message)? {
            return Ok(content);
        }
        if let Some(header_key) = self.ratchet.header_key_receiver()
            && let Some(header) = self.open_header(header_key, message)
        {
            return self.receive_current_chain(&header?, message);
        }
        if let Some(header) = self.open_header(self.ratchet.next_header_key_receiver(), message) {
            return self.receive_new_chain(&header?, message);
        }
        Err(ErrorKind::Undecryptable.into())
    }

    /// A message whose key was skipped earlier, because it arrived out of order.
    fn receive_skipped(&mut self, message: &EncryptedMessage) -> Result<Option<Vec<u8>>> {
        let header_keys = self
            .skipped_message_keys
            .keys()
            .map(|(k, _)| *k)
            .collect::<HashSet<_>>();
        for header_key in header_keys {
            if let Some(header) = self.open_header(header_key, message) {
                let skipped = (header_key, header?.message_number);
                let Some(&message_key) = self.skipped_message_keys.get(&skipped) else {
                    break;
                };
                let content = self.open_content(message_key, message)?;
                self.skipped_message_keys.remove(&skipped);
                return Ok(Some(content));
            }
        }
        Ok(None)
    }

    /// A message in the current receiving chain.
    fn receive_current_chain(
        &mut self,
        header: &Header,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        let message_number = header.message_number;
        // Earlier messages were received already or, if skipped, handled by `receive_skipped`.
        if message_number < self.message_number_receiver {
            return Err(ErrorKind::DuplicateMessage.into());
        }
        self.check_skip_count(message_number - self.message_number_receiver)?;

        let mut ratchet = self.ratchet.clone();
        let mut skipped = vec![];
        skip_message_keys(
            &mut ratchet,
            self.message_number_receiver,
            message_number,
            &mut skipped,
        )?;
        let message_key = ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        let content = self.open_content(message_key, message)?;

        self.ratchet = ratchet;
        self.skipped_message_keys.extend(skipped);
        self.message_number_receiver = message_number + 1;
        Ok(content)
    }

    /// The first message of the peer's next chain, which steps the DH-root ratchet.
    fn receive_new_chain(
        &mut self,
        header: &Header,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        let Header {
            previous_chain_length,
            message_number,
            ..
        } = *header;
        // The peer's previous chain cannot be shorter than what was received from it.
        if previous_chain_length < self.message_number_receiver {
            return Err(ErrorKind::InvalidHeader.into());
        }
        self.check_skip_count(
            (previous_chain_length - self.message_number_receiver).saturating_add(message_number),
        )?;

        let mut ratchet = self.ratchet.clone();
        let mut skipped = vec![];
        skip_message_keys(
            &mut ratchet,
            self.message_number_receiver,
            previous_chain_length,
            &mut skipped,
        )?;
        for _ in 0..2 {
            ratchet
                .step_dh_root(&header.public_key)
                .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;
        }
        skip_message_keys(&mut ratchet, 0, message_number, &mut skipped)?;
        let message_key = ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        let content = self.open_content(message_key, message)?;

        self.ratchet = ratchet;
        self.skipped_message_keys.extend(skipped);
        self.previous_chain_length = self.message_number_sender;
        self.message_number_sender = 0;
        self.message_number_receiver = message_number + 1;
        Ok(content)
    }

    /// Fails if skipping `count` more message keys would exceed [`SKIP_MAX`].
    fn check_skip_count(&self, count: u64) -> Result<()> {
        match (self.skipped_message_keys.len() as u64).checked_add(count) {
            Some(total) if total <= SKIP_MAX => Ok(()),
            _ => Err(ErrorKind::TooManySkipped.into()),
        }
    }

    /// Decrypt the header with `header_key`; None if it is not the key of this header.
    fn open_header(
        &self,
        header_key: HeaderKey,
        message: &EncryptedMessage,
    ) -> Option<Result<Header>> {
        let header = decrypt(
            header_key,
            &[b"Header"],
            &self.associated_data,
            &message.header,
        )
        .ok()?;
        Some(Header::decode(header.as_slice()).map_err(|e| Error::new(ErrorKind::InvalidHeader, e)))
    }

    fn open_content(&self, message_key: MessageKey, message: &EncryptedMessage) -> Result<Vec<u8>> {
        decrypt(
            message_key,
            &[b"Content"],
            &self.associated_data,
            &message.content,
        )
        .map_err(|e| Error::new(ErrorKind::Undecryptable, e))
    }
}

/// Step `ratchet`'s receiving chain from index `from` up to `until`, collecting the message keys.
fn skip_message_keys(
    ratchet: &mut Ratchet,
    from: u64,
    until: u64,
    skipped: &mut SkippedKeys,
) -> Result<()> {
    if from >= until {
        return Ok(());
    }
    let header_key = ratchet
        .header_key_receiver()
        .ok_or(ErrorKind::InvalidHeader)?;
    for message_number in from..until {
        let message_key = ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        skipped.push(((header_key, message_number), message_key));
    }
    Ok(())
}

/// AES-256-GCM key length.
const ENCRYPTION_KEY_LEN: usize = <Aes256Gcm as KeySizeUser>::KeySize::USIZE;
/// SHA-256 output length: the HKDF salt's and the HMAC-SHA256 key's length.
const HASH_LEN: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;
/// AES-GCM nonce length.
const NONCE_LEN: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;
/// HMAC-SHA256 tag length.
const TAG_LEN: usize = <Hmac<Sha256> as OutputSizeUser>::OutputSize::USIZE;

/// HKDF-SHA256 of `key`: the AES-256-GCM key, then the HMAC-SHA256 key.
fn derive_keys(key: &[u8], info: &[&[u8]]) -> ([u8; ENCRYPTION_KEY_LEN], [u8; HASH_LEN]) {
    let mut keys = [0; ENCRYPTION_KEY_LEN + HASH_LEN];
    Hkdf::<Sha256>::new(Some(&[0; HASH_LEN]), key)
        .expand_multi_info(info, &mut keys)
        .expect("two keys are a valid HKDF-SHA256 output length");
    let (encryption_key, authentication_key) = keys.split_at(ENCRYPTION_KEY_LEN);
    (
        encryption_key.try_into().unwrap(),
        authentication_key.try_into().unwrap(),
    )
}

/// Encrypt to `nonce || AES-256-GCM ciphertext || HMAC-SHA256(aad || nonce || ciphertext)`.
///
/// A header key encrypts every header of its chain, so each call draws a fresh random nonce.
fn encrypt(
    key: [u8; KEY_LENGTH],
    info: &[&[u8]],
    aad: &[u8],
    content: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    let (encryption_key, authentication_key) = derive_keys(&key, info);

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
    key: [u8; KEY_LENGTH],
    info: &[&[u8]],
    aad: &[u8],
    encrypted: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let (encryption_key, authentication_key) = derive_keys(&key, info);
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
    use ratchetx2::{DhPrivateKey, SharedKeys};

    use super::*;

    fn session() -> (Party, Party) {
        let keys = SharedKeys {
            secret_key: [1; 32],
            header_key_alice: [2; 32],
            header_key_bob: [3; 32],
        };
        let bob = keys.bob(DhPrivateKey::generate());
        let alice = keys.alice(&bob.public_key()).unwrap();
        (Party::new(alice, "AD"), Party::new(bob, "AD"))
    }

    #[test]
    fn bob_sends_only_after_receiving() {
        let (mut alice, mut bob) = session();
        assert_eq!(
            bob.encrypt(b"too early").unwrap_err().kind(),
            ErrorKind::NoSendingChain
        );
        let message = alice.encrypt(b"hi").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"hi");
        let message = bob.encrypt(b"hello").unwrap();
        assert_eq!(alice.decrypt(&message).unwrap(), b"hello");
    }

    #[test]
    fn out_of_order_and_duplicate_delivery() {
        let (mut alice, mut bob) = session();
        let sent: Vec<_> = ["m0", "m1", "m2"]
            .into_iter()
            .map(|content| alice.encrypt(content.as_bytes()).unwrap())
            .collect();
        assert_eq!(bob.decrypt(&sent[2]).unwrap(), b"m2");
        assert_eq!(bob.decrypt(&sent[0]).unwrap(), b"m0");
        assert_eq!(bob.decrypt(&sent[1]).unwrap(), b"m1");
        assert_eq!(
            bob.decrypt(&sent[0]).unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
        // The duplicate changed nothing.
        let message = alice.encrypt(b"m3").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"m3");
    }

    #[test]
    fn out_of_range_counter_is_rejected() {
        let (alice, mut bob) = session();
        // A message made from Alice's state, whose header claims u64::MAX earlier messages.
        let mut sender = alice.ratchet.clone();
        let header = Header {
            public_key: Bytes::from(sender.public_key()),
            previous_chain_length: 0,
            message_number: u64::MAX,
        };
        let message = EncryptedMessage {
            header: encrypt(
                sender.header_key_sender().unwrap(),
                &[b"Header"],
                b"AD",
                &header.encode_to_vec(),
            )
            .unwrap()
            .into(),
            content: encrypt(
                sender.step_message_ratchet_sender().unwrap(),
                &[b"Content"],
                b"AD",
                b"x",
            )
            .unwrap()
            .into(),
        };
        assert_eq!(
            bob.decrypt(&message).unwrap_err().kind(),
            ErrorKind::TooManySkipped
        );
        // Bob's state is unchanged: Alice's real first message still decrypts.
        let mut alice = alice;
        let message = alice.encrypt(b"hi").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"hi");
    }

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
