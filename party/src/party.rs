//! The party who participates in the E2EE chat.

use crate::error::{Error, ErrorKind, Result};
use crate::proto::{EncryptedMessage, Header};

use std::collections::HashMap;
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
    skipped_message_keys: SkippedKeys,
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
            .field("skipped", &self.skipped_count())
            .finish_non_exhaustive()
    }
}

/// Message keys skipped over while receiving: by the header key of their chain, then by message
/// number. A header key is only kept while its chain has skipped keys left.
type SkippedKeys = HashMap<HeaderKey, HashMap<u64, MessageKey>>;

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
            HEADER_INFO,
            &self.associated_data,
            &header.encode_to_vec(),
        )?;
        let message_key = self
            .ratchet
            .step_message_ratchet_sender()
            .ok_or(ErrorKind::NoSendingChain)?;
        self.message_number_sender += 1;
        let content = encrypt(
            message_key,
            CONTENT_INFO,
            &content_associated_data(&self.associated_data, &header),
            content,
        )?;
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
        let Some((header_key, header)) = self
            .skipped_message_keys
            .keys()
            .find_map(|&header_key| Some((header_key, self.open_header(header_key, message)?)))
        else {
            return Ok(None);
        };
        let header = header?;
        let Some(&message_key) = self.skipped_message_keys[&header_key].get(&header.message_number)
        else {
            return Ok(None);
        };
        let content = self.open_content(message_key, message)?;

        let message_keys = self
            .skipped_message_keys
            .get_mut(&header_key)
            .expect("the message key was found above");
        message_keys.remove(&header.message_number);
        if message_keys.is_empty() {
            self.skipped_message_keys.remove(&header_key);
        }
        Ok(Some(content))
    }

    /// A message in the current receiving chain.
    fn receive_current_chain(
        &mut self,
        header: &Header,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        // Earlier messages were received already or, if skipped, handled by `receive_skipped`.
        if header.message_number < self.message_number_receiver {
            return Err(ErrorKind::DuplicateMessage.into());
        }
        self.check_skip_count(header.message_number - self.message_number_receiver)?;

        let mut ratchet = self.ratchet.clone();
        let mut skipped = SkippedKeys::new();
        skip_message_keys(
            &mut ratchet,
            self.message_number_receiver,
            header.message_number,
            &mut skipped,
        )?;
        let message_key = ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        let content = self.open_content(message_key, message)?;

        self.ratchet = ratchet;
        self.keep_skipped(skipped);
        self.message_number_receiver = header.message_number + 1;
        Ok(content)
    }

    /// The first message of the peer's next chain, which steps the DH-root ratchet.
    fn receive_new_chain(
        &mut self,
        header: &Header,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        // The peer's previous chain cannot be shorter than what was received from it.
        if header.previous_chain_length < self.message_number_receiver {
            return Err(ErrorKind::InvalidHeader.into());
        }
        self.check_skip_count(
            (header.previous_chain_length - self.message_number_receiver)
                .saturating_add(header.message_number),
        )?;

        let mut ratchet = self.ratchet.clone();
        let mut skipped = SkippedKeys::new();
        skip_message_keys(
            &mut ratchet,
            self.message_number_receiver,
            header.previous_chain_length,
            &mut skipped,
        )?;
        for _ in 0..2 {
            ratchet
                .step_dh_root(&header.public_key)
                .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;
        }
        skip_message_keys(&mut ratchet, 0, header.message_number, &mut skipped)?;
        let message_key = ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        let content = self.open_content(message_key, message)?;

        self.ratchet = ratchet;
        self.keep_skipped(skipped);
        self.previous_chain_length = self.message_number_sender;
        self.message_number_sender = 0;
        self.message_number_receiver = header.message_number + 1;
        Ok(content)
    }

    /// Keep the message keys skipped while receiving a message, once it has decrypted.
    fn keep_skipped(&mut self, skipped: SkippedKeys) {
        for (header_key, message_keys) in skipped {
            self.skipped_message_keys
                .entry(header_key)
                .or_default()
                .extend(message_keys);
        }
    }

    /// Number of skipped message keys kept, over all chains.
    fn skipped_count(&self) -> usize {
        self.skipped_message_keys.values().map(HashMap::len).sum()
    }

    /// Fails if skipping `count` more message keys would exceed [`SKIP_MAX`].
    fn check_skip_count(&self, count: u64) -> Result<()> {
        match (self.skipped_count() as u64).checked_add(count) {
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
            HEADER_INFO,
            &self.associated_data,
            &message.header,
        )
        .ok()?;
        Some(Header::decode(header.as_slice()).map_err(|e| Error::new(ErrorKind::InvalidHeader, e)))
    }

    /// Decrypt the content with `message_key`; it only authenticates with the encrypted header
    /// it was sent with.
    fn open_content(&self, message_key: MessageKey, message: &EncryptedMessage) -> Result<Vec<u8>> {
        decrypt(
            message_key,
            CONTENT_INFO,
            &content_associated_data(&self.associated_data, &message.header),
            &message.content,
        )
        .map_err(|e| Error::new(ErrorKind::Undecryptable, e))
    }
}

/// The content's associated data: the session's associated data, then the encrypted header,
/// each prefixed with its length so that no other pair encodes the same.
///
/// The Double Ratchet spec authenticates the content with `AD || encrypted header`. Otherwise
/// someone with a header key could alter a header, e.g. its previous chain length so that the
/// receiver drops the keys of delayed messages, and the content would still decrypt.
fn content_associated_data(associated_data: &[u8], header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(2 * size_of::<u64>() + associated_data.len() + header.len());
    for part in [associated_data, header] {
        aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad
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
    let message_keys = skipped.entry(header_key).or_default();
    for message_number in from..until {
        let message_key = ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        message_keys.insert(message_number, message_key);
    }
    Ok(())
}

/// HKDF info of header encryption.
const HEADER_INFO: &[u8] = b"Header";
/// HKDF info of content encryption.
const CONTENT_INFO: &[u8] = b"Content";

/// AES-256-GCM key length.
const ENCRYPTION_KEY_LEN: usize = <Aes256Gcm as KeySizeUser>::KeySize::USIZE;
/// AES-GCM nonce length.
const GCM_NONCE_LEN: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;
/// SHA-256 output length: the HKDF salt's and the HMAC-SHA256 key's length.
const HASH_LEN: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;
/// Length of the random nonce of each encryption.
const NONCE_LEN: usize = HASH_LEN;
/// HMAC-SHA256 tag length.
const TAG_LEN: usize = <Hmac<Sha256> as OutputSizeUser>::OutputSize::USIZE;

// The Double Ratchet spec asks header encryption, whose key is reused, for random nonces of at
// least 128 bits.
const _: () = assert!(NONCE_LEN * 8 >= 128);

/// HKDF-SHA256 of `key`, with `info` and the encryption's `nonce` as info: the AES-256-GCM key
/// and nonce, then the HMAC-SHA256 key.
fn derive_keys(
    key: &[u8],
    info: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> (
    [u8; ENCRYPTION_KEY_LEN],
    [u8; GCM_NONCE_LEN],
    [u8; HASH_LEN],
) {
    let mut keys = [0; ENCRYPTION_KEY_LEN + GCM_NONCE_LEN + HASH_LEN];
    Hkdf::<Sha256>::new(Some(&[0; HASH_LEN]), key)
        .expand_multi_info(&[info, nonce], &mut keys)
        .expect("the keys are a valid HKDF-SHA256 output length");
    let (encryption_key, rest) = keys.split_at(ENCRYPTION_KEY_LEN);
    let (gcm_nonce, authentication_key) = rest.split_at(GCM_NONCE_LEN);
    (
        encryption_key.try_into().unwrap(),
        gcm_nonce.try_into().unwrap(),
        authentication_key.try_into().unwrap(),
    )
}

/// Encrypt to `nonce || AES-256-GCM ciphertext || HMAC-SHA256(aad || nonce || ciphertext)`.
///
/// A header key encrypts every header of its chain, so AES-GCM must never see one key and nonce
/// twice. Each call draws a random 256-bit nonce and derives the AES-GCM key and nonce from `key`
/// and it: two calls only share them if they draw the same nonce, and there is no counter to
/// keep, persist or roll back.
fn encrypt(
    key: [u8; KEY_LENGTH],
    info: &[u8],
    aad: &[u8],
    content: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError)?;
    let (encryption_key, gcm_nonce, authentication_key) = derive_keys(&key, info, &nonce);

    let mut out = nonce.to_vec();
    out.extend(
        Aes256Gcm::new(&encryption_key.into())
            .encrypt(&gcm_nonce.into(), Payload { msg: content, aad })
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
    info: &[u8],
    aad: &[u8],
    encrypted: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let (nonce_and_ciphertext, tag) = encrypted.split_at(encrypted.len() - TAG_LEN);
    let (nonce, ciphertext) = nonce_and_ciphertext.split_at(NONCE_LEN);
    let (encryption_key, gcm_nonce, authentication_key) =
        derive_keys(&key, info, nonce.try_into().unwrap());

    let mut hmac = Hmac::<Sha256>::new_from_slice(&authentication_key).unwrap();
    hmac.update(aad);
    hmac.update(nonce_and_ciphertext);
    hmac.verify_slice(tag).map_err(|_| CryptoError)?;

    Aes256Gcm::new(&encryption_key.into())
        .decrypt(
            &gcm_nonce.into(),
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

    /// What a rejected message must leave as it was. (`Ratchet`'s `PartialEq` compares with the
    /// peer's ratchet, so this takes what the party would use next instead.)
    fn state(party: &Party) -> impl PartialEq + fmt::Debug + use<> {
        let mut ratchet = party.ratchet.clone();
        (
            ratchet.public_key(),
            ratchet.header_key_receiver(),
            ratchet.next_header_key_receiver(),
            ratchet.step_message_ratchet_receiver(),
            party.skipped_message_keys.clone(),
            party.previous_chain_length,
            party.message_number_sender,
            party.message_number_receiver,
        )
    }

    /// `message` with its header decrypted, `alter`ed and encrypted again, by someone who has
    /// the header key but not the message key.
    fn reencrypt_header(
        receiver: &Party,
        header_key: HeaderKey,
        message: &EncryptedMessage,
        alter: impl FnOnce(&mut Header),
    ) -> EncryptedMessage {
        let mut header = receiver.open_header(header_key, message).unwrap().unwrap();
        alter(&mut header);
        let header = encrypt(header_key, HEADER_INFO, b"AD", &header.encode_to_vec()).unwrap();
        EncryptedMessage {
            header: header.into(),
            content: message.content.clone(),
        }
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
        // Both skipped keys are used up, and with them their chain's header key.
        assert!(bob.skipped_message_keys.is_empty());
        assert_eq!(
            bob.decrypt(&sent[0]).unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
        // The duplicate changed nothing.
        let message = alice.encrypt(b"m3").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"m3");
    }

    #[test]
    fn delayed_messages_across_dh_steps() {
        let (mut alice, mut bob) = session();
        let a0 = alice.encrypt(b"a0").unwrap();
        let a1 = alice.encrypt(b"a1").unwrap();
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
        let b0 = bob.encrypt(b"b0").unwrap();
        let b1 = bob.encrypt(b"b1").unwrap();
        assert_eq!(alice.decrypt(&b1).unwrap(), b"b1");
        let a2 = alice.encrypt(b"a2").unwrap();
        assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
        let b2 = bob.encrypt(b"b2").unwrap();
        assert_eq!(alice.decrypt(&b2).unwrap(), b"b2");
        // Each arrives after its receiver has moved on to the sender's next chain.
        assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");
        assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");
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
        let header = encrypt(
            sender.header_key_sender().unwrap(),
            HEADER_INFO,
            b"AD",
            &header.encode_to_vec(),
        )
        .unwrap();
        let content = encrypt(
            sender.step_message_ratchet_sender().unwrap(),
            CONTENT_INFO,
            &content_associated_data(b"AD", &header),
            b"x",
        )
        .unwrap();
        let message = EncryptedMessage {
            header: header.into(),
            content: content.into(),
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
    fn altered_previous_chain_length_is_rejected() {
        let (mut alice, mut bob) = session();
        let m0 = alice.encrypt(b"m0").unwrap();
        let delayed = alice.encrypt(b"m1").unwrap();
        assert_eq!(bob.decrypt(&m0).unwrap(), b"m0");
        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap(), b"reply");
        // The first message of Alice's next chain: her previous chain had 2 messages.
        let next = alice.encrypt(b"next").unwrap();

        // The header says 1 instead, the number Bob has received, so Bob would not keep the
        // delayed message's key. It still opens with the header key and selects the same
        // message key.
        let header_key = bob.ratchet.next_header_key_receiver();
        let forged = reencrypt_header(&bob, header_key, &next, |header| {
            assert_eq!(header.previous_chain_length, 2);
            header.previous_chain_length = 1;
        });
        let before = state(&bob);
        assert_eq!(
            bob.decrypt(&forged).unwrap_err().kind(),
            ErrorKind::Undecryptable
        );
        assert_eq!(state(&bob), before);
        assert_eq!(bob.decrypt(&next).unwrap(), b"next");
        assert_eq!(bob.decrypt(&delayed).unwrap(), b"m1");
    }

    #[test]
    fn replaced_header_fails_content_authentication() {
        let (mut alice, mut bob) = session();
        let sent: Vec<_> = ["m0", "m1", "m2", "m3"]
            .into_iter()
            .map(|content| alice.encrypt(content.as_bytes()).unwrap())
            .collect();
        // Bob keeps the keys of m0 and m1.
        assert_eq!(bob.decrypt(&sent[2]).unwrap(), b"m2");

        // Headers that open with the header key and select the same message key: m0's
        // encrypted again, for a skipped key, and m3's with another previous chain length, in
        // the current chain.
        let header_key = bob.ratchet.header_key_receiver().unwrap();
        let forged = [
            reencrypt_header(&bob, header_key, &sent[0], |_| {}),
            reencrypt_header(&bob, header_key, &sent[3], |header| {
                header.previous_chain_length += 1;
            }),
        ];
        for forged in &forged {
            let before = state(&bob);
            assert_eq!(
                bob.decrypt(forged).unwrap_err().kind(),
                ErrorKind::Undecryptable
            );
            // Including the skipped message keys: m0's is not used up.
            assert_eq!(state(&bob), before);
        }
        assert_eq!(bob.decrypt(&sent[0]).unwrap(), b"m0");
        assert_eq!(bob.decrypt(&sent[3]).unwrap(), b"m3");
        assert_eq!(bob.decrypt(&sent[1]).unwrap(), b"m1");
    }

    #[test]
    fn every_nonce_bit_changes_the_aes_gcm_key_and_nonce() {
        // A header key encrypts its chain's headers under nonces that differ in some bits.
        let header_key = [7; 32];
        let (encryption_key, gcm_nonce, authentication_key) =
            derive_keys(&header_key, HEADER_INFO, &[0; NONCE_LEN]);
        for bit in 0..NONCE_LEN * 8 {
            let mut nonce = [0; NONCE_LEN];
            nonce[bit / 8] ^= 1 << (bit % 8);
            let keys = derive_keys(&header_key, HEADER_INFO, &nonce);
            assert_ne!(keys.0, encryption_key);
            assert_ne!(keys.1, gcm_nonce);
            assert_ne!(keys.2, authentication_key);
        }
        // Headers and contents never share keys, even when a header key equals a message key.
        let keys = derive_keys(&header_key, CONTENT_INFO, &[0; NONCE_LEN]);
        assert_ne!(keys.0, encryption_key);
        assert_ne!(keys.2, authentication_key);
    }

    #[test]
    fn encryption_authenticates_nonce_and_associated_data() {
        let header_key = [7; 32];
        let a = encrypt(header_key, HEADER_INFO, b"ad", b"same header").unwrap();
        let b = encrypt(header_key, HEADER_INFO, b"ad", b"same header").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            decrypt(header_key, HEADER_INFO, b"ad", &a).unwrap(),
            b"same header"
        );
        assert_eq!(
            decrypt(header_key, HEADER_INFO, b"ad", &b).unwrap(),
            b"same header"
        );

        for byte in [0, NONCE_LEN - 1, NONCE_LEN, a.len() - 1] {
            let mut tampered = a.clone();
            tampered[byte] ^= 1;
            assert!(decrypt(header_key, HEADER_INFO, b"ad", &tampered).is_err());
        }
        assert!(decrypt(header_key, HEADER_INFO, b"other ad", &a).is_err());
        assert!(decrypt(header_key, CONTENT_INFO, b"ad", &a).is_err());
        assert!(
            decrypt(
                header_key,
                HEADER_INFO,
                b"ad",
                &a[..NONCE_LEN + TAG_LEN - 1]
            )
            .is_err()
        );
    }

    #[test]
    fn content_associated_data_is_unambiguous() {
        assert_ne!(
            content_associated_data(b"AD", b"header"),
            content_associated_data(b"ADh", b"eader")
        );
        assert_ne!(
            content_associated_data(b"", b"header"),
            content_associated_data(b"header", b"")
        );
    }
}
