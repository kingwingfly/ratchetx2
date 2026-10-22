//! The party who participates in the E2EE chat.

use crate::error::{Error, ErrorKind, Result};
use crate::transport::{EncryptedMessage, LocalTransport};

use std::collections::{HashMap, HashSet};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message as _;
use ratchetx2::{
    Ratchet,
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
/// let alice_ratchetx2 = shared_keys.alice(&bob_ratchetx2.public_key()).unwrap();
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
pub struct Party<T: LocalTransport> {
    ratchetx2: Ratchet,
    transport: T,
    /// (HeaderKey, N)
    skipped_mk: HashMap<(HeaderKey, usize), MessageKey>,
    pn: usize,
    ns: usize,
    nr: usize,
    associated_data: Vec<u8>,
}

/// Message keys skipped over while receiving, keyed like [`Party`]'s `skipped_mk`.
type SkippedKeys = Vec<((HeaderKey, usize), MessageKey)>;

impl<T: LocalTransport> Party<T> {
    /// New a party.
    ///
    /// # Args
    /// - associated_data: used in enryption
    pub fn new(ratchetx2: Ratchet, transport: T, associated_data: impl AsRef<[u8]>) -> Self {
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
    ///
    /// Bob has no sending chain until he has received Alice's first message;
    /// until then this returns an error.
    /// # Args
    /// - content: the bytes to push, not encrypted
    pub async fn push(&mut self, content: impl AsRef<[u8]>) -> Result<()> {
        let header_key = self
            .ratchetx2
            .header_key_s()
            .ok_or(ErrorKind::NoSendingChain)?;
        let header = Header {
            public_key: self.ratchetx2.public_key(),
            pn: self.pn as u64,
            n: self.ns as u64,
        };
        let enc_header = encrypt(
            header_key,
            &[b"Header"],
            &self.associated_data,
            &header.encode_to_vec(),
        )?;

        let message_key = self
            .ratchetx2
            .step_msgs()
            .ok_or(ErrorKind::NoSendingChain)?;
        // The key is used up even if the push below fails; counting the message keeps `n` in step
        // with the chain, so the peer skips a lost message instead of failing on every later one.
        self.ns += 1;
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
        Ok(())
    }

    /// Fetch and decrypt messages.
    ///
    /// Returns decrypted bytes.
    pub async fn fetch(&mut self) -> Result<Vec<Result<Vec<u8>>>> {
        let encrypted_messages = self.transport.fetch(None).await?;
        Ok(encrypted_messages
            .into_iter()
            .map(|encrypted_message| self.receive(&encrypted_message?))
            .collect())
    }

    /// Decrypt one message. The state only changes if the content decrypts.
    fn receive(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        if let Some(content) = self.receive_skipped(message)? {
            return Ok(content);
        }
        if let Some(header_key) = self.ratchetx2.header_key_r()
            && let Some(header) = self.open_header(header_key, message)
        {
            return self.receive_current_chain(&header?, message);
        }
        if let Some(header) = self.open_header(self.ratchetx2.next_header_key_r(), message) {
            return self.receive_new_chain(&header?, message);
        }
        Err(ErrorKind::Undecryptable.into())
    }

    /// A message whose key was skipped earlier, because it arrived out of order.
    fn receive_skipped(&mut self, message: &EncryptedMessage) -> Result<Option<Vec<u8>>> {
        let header_keys = self
            .skipped_mk
            .keys()
            .map(|(k, _)| *k)
            .collect::<HashSet<_>>();
        for header_key in header_keys {
            if let Some(header) = self.open_header(header_key, message) {
                let skipped = (header_key, to_index(header?.n)?);
                let Some(&message_key) = self.skipped_mk.get(&skipped) else {
                    break;
                };
                let content = self.open_content(message_key, message)?;
                self.skipped_mk.remove(&skipped);
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
        let n = to_index(header.n)?;
        // Earlier messages were received already or, if skipped, handled by `receive_skipped`.
        if n < self.nr {
            return Err(ErrorKind::DuplicateMessage.into());
        }
        self.check_skip_count(n - self.nr)?;

        let mut ratchetx2 = self.ratchetx2.clone();
        let mut skipped = vec![];
        skip_message_keys(&mut ratchetx2, self.nr, n, &mut skipped)?;
        let message_key = ratchetx2.step_msgr().ok_or(ErrorKind::InvalidHeader)?;
        let content = self.open_content(message_key, message)?;

        self.ratchetx2 = ratchetx2;
        self.skipped_mk.extend(skipped);
        self.nr = n + 1;
        Ok(content)
    }

    /// The first message of the peer's next chain, which steps the DH-root ratchet.
    fn receive_new_chain(
        &mut self,
        header: &Header,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        let (pn, n) = (to_index(header.pn)?, to_index(header.n)?);
        // The peer's previous chain cannot be shorter than what was received from it.
        if pn < self.nr {
            return Err(ErrorKind::InvalidHeader.into());
        }
        self.check_skip_count((pn - self.nr).saturating_add(n))?;

        let mut ratchetx2 = self.ratchetx2.clone();
        let mut skipped = vec![];
        skip_message_keys(&mut ratchetx2, self.nr, pn, &mut skipped)?;
        for _ in 0..2 {
            ratchetx2
                .step_dh_root(&header.public_key)
                .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;
        }
        skip_message_keys(&mut ratchetx2, 0, n, &mut skipped)?;
        let message_key = ratchetx2.step_msgr().ok_or(ErrorKind::InvalidHeader)?;
        let content = self.open_content(message_key, message)?;

        self.ratchetx2 = ratchetx2;
        self.skipped_mk.extend(skipped);
        self.pn = self.ns;
        self.ns = 0;
        self.nr = n + 1;
        Ok(content)
    }

    /// Fails if skipping `count` more message keys would exceed [`SKIP_MAX`].
    fn check_skip_count(&self, count: usize) -> Result<()> {
        match self.skipped_mk.len().checked_add(count) {
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
            &message.enc_header,
        )
        .ok()?;
        Some(Header::decode(header.as_slice()).map_err(|e| Error::new(ErrorKind::InvalidHeader, e)))
    }

    fn open_content(&self, message_key: MessageKey, message: &EncryptedMessage) -> Result<Vec<u8>> {
        decrypt(
            message_key,
            &[b"Content"],
            &self.associated_data,
            &message.enc_content,
        )
        .map_err(|e| Error::new(ErrorKind::Undecryptable, e))
    }
}

/// Step `ratchetx2`'s receiving chain from index `from` up to `until`, collecting the message keys.
fn skip_message_keys(
    ratchetx2: &mut Ratchet,
    from: usize,
    until: usize,
    skipped: &mut SkippedKeys,
) -> Result<()> {
    if from >= until {
        return Ok(());
    }
    let header_key = ratchetx2.header_key_r().ok_or(ErrorKind::InvalidHeader)?;
    for n in from..until {
        let message_key = ratchetx2.step_msgr().ok_or(ErrorKind::InvalidHeader)?;
        skipped.push(((header_key, n), message_key));
    }
    Ok(())
}

/// A header counter as an index; it can be out of range on 32-bit targets such as wasm32.
fn to_index(counter: u64) -> Result<usize> {
    usize::try_from(counter).map_err(|e| Error::new(ErrorKind::InvalidHeader, e))
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
    use ratchetx2::{DhPrivateKey, SharedKeys};

    use super::*;
    use crate::transport::ChannelTransport;

    fn session() -> (Ratchet, Ratchet) {
        let keys = SharedKeys {
            secret_key: [1; 32],
            header_key_alice: [2; 32],
            header_key_bob: [3; 32],
        };
        let bob = keys.bob(DhPrivateKey::generate());
        let alice = keys.alice(&bob.public_key()).unwrap();
        (alice, bob)
    }

    #[tokio::test]
    async fn bob_sends_only_after_receiving() {
        let (alice, bob) = session();
        let (a, b) = ChannelTransport::new();
        let (mut alice, mut bob) = (Party::new(alice, a, "AD"), Party::new(bob, b, "AD"));
        assert_eq!(
            bob.push("too early").await.unwrap_err().kind(),
            ErrorKind::NoSendingChain
        );
        alice.push("hi").await.unwrap();
        assert_eq!(bob.fetch().await.unwrap().remove(0).unwrap(), b"hi");
        bob.push("hello").await.unwrap();
        assert_eq!(alice.fetch().await.unwrap().remove(0).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn out_of_order_and_duplicate_delivery() {
        let (alice, bob) = session();
        let (a, b) = ChannelTransport::new();
        // Clones share the channels, standing in for a network that reorders and redelivers.
        let (mut network_in, mut network_out) = (b.clone(), a.clone());
        let (mut alice, mut bob) = (Party::new(alice, a, "AD"), Party::new(bob, b, "AD"));
        for content in ["m0", "m1", "m2"] {
            alice.push(content).await.unwrap();
        }
        let sent = LocalTransport::fetch_bytes(&mut network_in, None)
            .await
            .unwrap();
        for i in [2, 0, 1, 0] {
            LocalTransport::push_bytes(&mut network_out, sent[i].clone())
                .await
                .unwrap();
        }
        let received = bob.fetch().await.unwrap();
        assert_eq!(received[0].as_deref().unwrap(), b"m2");
        assert_eq!(received[1].as_deref().unwrap(), b"m0");
        assert_eq!(received[2].as_deref().unwrap(), b"m1");
        assert_eq!(
            received[3].as_ref().unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
        // ... and changes nothing.
        alice.push("m3").await.unwrap();
        assert_eq!(bob.fetch().await.unwrap().remove(0).unwrap(), b"m3");
    }

    #[tokio::test]
    async fn out_of_range_counter_is_rejected() {
        let (alice, bob) = session();
        let (a, b) = ChannelTransport::new();
        let mut network_out = a.clone();
        // A message made from Alice's state, whose header claims u64::MAX earlier messages.
        let mut sender = alice.clone();
        let header = Header {
            public_key: sender.public_key(),
            pn: 0,
            n: u64::MAX,
        };
        let message = EncryptedMessage {
            enc_header: encrypt(
                sender.header_key_s().unwrap(),
                &[b"Header"],
                b"AD",
                &header.encode_to_vec(),
            )
            .unwrap(),
            enc_content: encrypt(sender.step_msgs().unwrap(), &[b"Content"], b"AD", b"x").unwrap(),
        };
        LocalTransport::push(&mut network_out, message)
            .await
            .unwrap();
        let (mut alice, mut bob) = (Party::new(alice, a, "AD"), Party::new(bob, b, "AD"));
        assert_eq!(
            bob.fetch().await.unwrap().remove(0).unwrap_err().kind(),
            ErrorKind::TooManySkipped
        );
        // Bob's state is unchanged: Alice's real first message still decrypts.
        alice.push("hi").await.unwrap();
        assert_eq!(bob.fetch().await.unwrap().remove(0).unwrap(), b"hi");
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
