//! The party who participates in the E2EE chat.

mod kem;
mod skipped;
#[cfg(feature = "serde")]
mod wire;
#[cfg(all(feature = "serde", has_pq))]
pub use wire::LegacyPartyPqV1;
#[cfg(feature = "serde")]
pub use wire::{LegacyPartyV0, LegacyPartyV1};

use std::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit, KeySizeUser,
    aead::{Aead, AeadCore, Payload, array::typenum::Unsigned},
};
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, digest::OutputSizeUser};
use prost::Message as _;
#[cfg(all(test, has_pq))]
use ratchetx2::pq::KEM_KEY_ID_LENGTH;
#[cfg(all(feature = "serde", has_pq))]
use ratchetx2::pq::KemRatchet;
#[cfg(has_pq)]
use ratchetx2::pq::{KemRatchetConfig, PqSuite};
use ratchetx2::{
    Ratchet,
    error::CryptoError,
    key::{HeaderKey, KEY_LENGTH, MessageKey},
};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use self::kem::KemState;
use self::skipped::{EvictedSet, SkippedChain, SkippedKeys};
use crate::{
    error::{Error, ErrorKind, Result},
    proto::{EncryptedMessage, Header},
};

/// Maximum number of message keys that receiving one message may skip, and that are kept for
/// messages arriving late; beyond it, the oldest are dropped.
pub const SKIP_MAX: u64 = 1024;
/// Number of the peer's chains, its current one and those before, whose skipped message keys are
/// kept; a message delayed longer cannot be decrypted.
pub const MAX_SKIPPED_CHAINS: usize = 5;

#[cfg(has_pq)]
const _: () = assert!(ratchetx2::pq::MAX_ENCAPSULATED_HISTORY > MAX_SKIPPED_CHAINS);

/// The party who participates in the E2EE chat: encrypts and decrypts messages, without I/O.
/// See the example in the [crate docs](crate).
///
/// To keep a session between runs, it converts to and from `proto::Party` with the `prost`
/// feature (portable versioned persistence), and serializes with `serde`, all with its keys:
/// keep the output secret.
///
/// Serde version 2 starts with version and capability bytes. Capability 0 identifies a
/// classical party, 1 identifies ML-KEM-1024, and 2 identifies ML-KEM-768. The final
/// field is the KEM state option in every build.
#[cfg_attr(
    all(feature = "serde", not(has_pq)),
    doc = "For unversioned positional records, select [`LegacyPartyV0`] or [`LegacyPartyV1`] using the enclosing storage format."
)]
#[cfg_attr(
    all(feature = "serde", has_pq),
    doc = "For unversioned positional records, select [`LegacyPartyV0`], [`LegacyPartyV1`], or [`LegacyPartyPqV1`] using the enclosing storage format."
)]
pub struct Party {
    ratchet: Ratchet,
    /// Keys of the messages skipped over while receiving, for when they arrive late.
    skipped_message_keys: SkippedKeys,
    /// Number of messages in the previous sending chain.
    previous_chain_length: u64,
    /// Number of the next message to send in the current sending chain.
    message_number_sender: u64,
    /// Number of the next message expected in the current receiving chain.
    message_number_receiver: u64,
    associated_data: Vec<u8>,
    /// Message numbers whose skipped keys were evicted on the current receiving chain.
    current_chain_evicted: EvictedSet,
    /// Optional post-quantum KEM ratchet state (`None` in classical sessions; zero-sized when no
    /// ML-KEM suite is compiled in).
    kem_ratchet: KemState,
}

/// Crate-private tentative staging transaction for `(Ratchet, KemState)` mutations.
///
/// Clones only `(Ratchet, KemState)` (never [`SkippedKeys`]) so failed encrypt/decrypt paths
/// leave the [`Party`] untouched and zeroize staged secret material on drop.
struct RatchetTx<'a> {
    party: &'a mut Party,
    ratchet: Ratchet,
    kem: KemState,
}

impl<'a> RatchetTx<'a> {
    fn begin(party: &'a mut Party) -> Self {
        let ratchet = party.ratchet.clone();
        let kem = party.kem_ratchet.clone();
        Self {
            party,
            ratchet,
            kem,
        }
    }

    /// Commit staged `(Ratchet, KemState)` into `self.party`; the replaced pre-step state is
    /// swapped into `self` and zeroized on drop.
    fn commit(mut self) {
        core::mem::swap(&mut self.party.ratchet, &mut self.ratchet);
        core::mem::swap(&mut self.party.kem_ratchet, &mut self.kem);
    }
}

impl Drop for RatchetTx<'_> {
    fn drop(&mut self) {
        self.ratchet.zeroize();
        self.kem.zeroize();
    }
}

/// Outcome of checking skipped chains during [`Party::decrypt`].
enum SkippedOutcome {
    /// Decrypted a delayed message from a skipped key.
    Decrypted(Vec<u8>),
    /// Header opened under the current receiving chain's header key (reused without decrypting
    /// the header a second time).
    CurrentChain(Header),
    /// Header did not match any skipped chain.
    NotMatched,
}

impl fmt::Debug for Party {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Party");
        s.field("previous_chain_length", &self.previous_chain_length)
            .field("message_number_sender", &self.message_number_sender)
            .field("message_number_receiver", &self.message_number_receiver)
            .field("skipped", &self.skipped_message_keys.len())
            .field("pq_active", &self.is_pq_ratchet_active());
        s.finish_non_exhaustive()
    }
}

impl Party {
    /// Creates a party that binds `associated_data` to each encrypted message.
    ///
    /// The ratchet must be at a message boundary, with [`Ratchet::dh_step_updates_sender`]
    /// equal to `false`. Use a fresh [`Ratchet::alice`] or [`Ratchet::bob`], or finish both
    /// DH steps of a receiving turn before passing the ratchet here.
    pub fn new(ratchet: Ratchet, associated_data: impl AsRef<[u8]>) -> Self {
        Self {
            ratchet,
            skipped_message_keys: SkippedKeys::default(),
            previous_chain_length: 0,
            message_number_sender: 0,
            message_number_receiver: 0,
            associated_data: associated_data.as_ref().to_vec(),
            current_chain_evicted: EvictedSet::default(),
            kem_ratchet: KemState::disabled(),
        }
    }

    /// Create a party with post-quantum KEM ratcheting enabled using default cadence.
    /// The ratchet must meet the message-boundary precondition of [`Self::new`].
    #[cfg(has_pq)]
    pub fn new_pq(ratchet: Ratchet, associated_data: impl AsRef<[u8]>, suite: PqSuite) -> Self {
        Self::new_pq_with_config(ratchet, associated_data, suite, KemRatchetConfig::default())
    }

    /// Create a party with post-quantum KEM ratcheting enabled and custom rekey cadence.
    /// The ratchet must meet the message-boundary precondition of [`Self::new`].
    #[cfg(has_pq)]
    pub fn new_pq_with_config(
        ratchet: Ratchet,
        associated_data: impl AsRef<[u8]>,
        suite: PqSuite,
        config: KemRatchetConfig,
    ) -> Self {
        let mut party = Self::new(ratchet, associated_data);
        party.kem_ratchet = KemState::enabled(suite, config);
        party
    }

    /// Enable post-quantum KEM ratcheting on this party using default cadence.
    ///
    /// If the same `suite` is already enabled, this is a no-op so pending KEM offer seeds and
    /// active ciphertexts are preserved. Returns [`ErrorKind::Crypto`] if a different PQ suite
    /// is already enabled.
    #[cfg(has_pq)]
    pub fn enable_pq_ratchet(&mut self, suite: PqSuite) -> Result<()> {
        self.enable_pq_ratchet_with_config(suite, KemRatchetConfig::default())
    }

    /// Enable post-quantum KEM ratcheting on this party with custom rekey cadence.
    ///
    /// If the same `suite` is already enabled, this is a no-op so pending KEM offer seeds and
    /// active ciphertexts are preserved. Returns [`ErrorKind::Crypto`] if a different PQ suite
    /// is already enabled.
    #[cfg(has_pq)]
    pub fn enable_pq_ratchet_with_config(
        &mut self,
        suite: PqSuite,
        config: KemRatchetConfig,
    ) -> Result<()> {
        self.kem_ratchet.enable(suite, config)
    }

    /// The configured post-quantum KEM suite, if PQ ratcheting is enabled.
    #[cfg(has_pq)]
    pub fn pq_suite(&self) -> Option<PqSuite> {
        self.kem_ratchet.suite()
    }

    /// Wire identifier (`1` = ML-KEM-1024, `2` = ML-KEM-768) of the active PQ KEM suite, if any.
    pub fn pq_suite_id(&self) -> Option<u8> {
        self.kem_ratchet.suite_id()
    }

    /// Associated data bound to every header and message in this session.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    /// Whether post-quantum KEM ratcheting is active on this party.
    pub fn is_pq_ratchet_active(&self) -> bool {
        self.kem_ratchet.is_active()
    }

    /// Encrypt a message. The party's state only advances if RNG and AEAD encryption succeed.
    ///
    /// Bob has no sending chain until he has decrypted Alice's first message;
    /// until then this returns an error.
    pub fn encrypt(&mut self, content: &[u8]) -> Result<EncryptedMessage> {
        let next_message_number = self
            .message_number_sender
            .checked_add(1)
            .ok_or(ErrorKind::Crypto)?;

        let mut tx = RatchetTx::begin(self);
        let header_key = tx
            .ratchet
            .header_key_sender()
            .ok_or(ErrorKind::NoSendingChain)?;
        let kem_fields = tx.kem.prepare_send()?;

        let header = Header {
            public_key: Bytes::copy_from_slice(&tx.ratchet.public_key()),
            previous_chain_length: tx.party.previous_chain_length,
            message_number: tx.party.message_number_sender,
            pq_suite: kem_fields.pq_suite,
            pq_public_key: kem_fields.pq_public_key,
            pq_ciphertext: kem_fields.pq_ciphertext,
            pq_key_id: kem_fields.pq_key_id,
        };
        let header_bytes = Zeroizing::new(header.encode_to_vec());
        let header = encrypt(
            &header_key,
            HEADER_INFO,
            &tx.party.associated_data,
            &header_bytes,
        )?;
        let message_key = tx
            .ratchet
            .step_message_ratchet_sender()
            .ok_or(ErrorKind::NoSendingChain)?;
        let content = encrypt(
            &message_key,
            CONTENT_INFO,
            &content_associated_data(&tx.party.associated_data, &header),
            content,
        )?;

        // Commit state only after both fallible encryptions succeed.
        tx.commit();
        self.message_number_sender = next_message_number;
        Ok(EncryptedMessage {
            header: Bytes::from(header),
            content: Bytes::from(content),
        })
    }

    /// Decrypt a message. The state only changes if the content decrypts.
    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        match self.receive_skipped(message)? {
            SkippedOutcome::Decrypted(content) => return Ok(content),
            SkippedOutcome::CurrentChain(header) => {
                return self.receive_current_chain(&header, message);
            }
            SkippedOutcome::NotMatched => {}
        }
        if let Some(header_key) = self.ratchet.header_key_receiver()
            && let Some(header) = self.open_header(&header_key, message)
        {
            return self.receive_current_chain(&header?, message);
        }
        let next_header_key = self.ratchet.next_header_key_receiver();
        if let Some(header) = self.open_header(&next_header_key, message) {
            return self.receive_next_chain(&header?, message);
        }
        Err(ErrorKind::Undecryptable.into())
    }

    /// A message whose key was skipped earlier, because it arrived out of order.
    fn receive_skipped(&mut self, message: &EncryptedMessage) -> Result<SkippedOutcome> {
        let Some((header_key, header)) =
            self.skipped_message_keys
                .header_keys()
                .find_map(|header_key| {
                    let header = self.open_header(header_key, message)?;
                    Some((Zeroizing::new(*header_key), header))
                })
        else {
            return Ok(SkippedOutcome::NotMatched);
        };
        let header = header?;
        let Some(message_key) = self
            .skipped_message_keys
            .get(&header_key, header.message_number)
        else {
            if self
                .skipped_message_keys
                .is_evicted(&header_key, header.message_number)
            {
                return Err(ErrorKind::EvictedMessage.into());
            }
            // If this header key is the current receiving chain's key, hand the already-opened
            // header straight to `receive_current_chain` (avoiding a second header trial-decrypt).
            if self
                .ratchet
                .header_key_receiver()
                .is_some_and(|cur| bool::from(cur.ct_eq(&*header_key)))
            {
                return Ok(SkippedOutcome::CurrentChain(header));
            }
            // Otherwise, this header belongs to a closed older chain still present in
            // `skipped_message_keys` whose key was neither kept nor evicted: it was already
            // received, so report `DuplicateMessage` rather than stalling as `Undecryptable`.
            return Err(ErrorKind::DuplicateMessage.into());
        };
        let mut tx = RatchetTx::begin(self);
        tx.kem.receive_skipped(&header)?;
        let content = open_content(&tx.party.associated_data, &message_key, message)?;
        tx.commit();
        self.skipped_message_keys
            .remove(&header_key, header.message_number);
        Ok(SkippedOutcome::Decrypted(content))
    }

    /// A message in the current receiving chain.
    fn receive_current_chain(
        &mut self,
        header: &Header,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        // Earlier messages were either received already, skipped (handled by `receive_skipped`),
        // or had their skipped keys evicted before arrival.
        if header.message_number < self.message_number_receiver {
            if self.current_chain_evicted.contains(header.message_number) {
                return Err(ErrorKind::EvictedMessage.into());
            }
            return Err(ErrorKind::DuplicateMessage.into());
        }
        check_skip_count(header.message_number - self.message_number_receiver)?;
        let next_message_number_receiver = header
            .message_number
            .checked_add(1)
            .ok_or(ErrorKind::InvalidHeader)?;

        let mut tx = RatchetTx::begin(self);
        tx.kem.receive_current_chain(header)?;
        let skipped = skip_message_keys(
            &mut tx.ratchet,
            tx.party.message_number_receiver,
            header.message_number,
        )?;
        let message_key = tx
            .ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        let content = open_content(&tx.party.associated_data, &message_key, message)?;

        let current_recv_hk = tx.ratchet.header_key_receiver();
        tx.commit();
        self.skipped_message_keys
            .extend_with_evictions(skipped, |evicted_hk, msg_num| {
                if current_recv_hk
                    .as_ref()
                    .is_some_and(|cur| bool::from(cur.ct_eq(evicted_hk)))
                {
                    self.current_chain_evicted.insert(msg_num);
                }
            });
        self.message_number_receiver = next_message_number_receiver;
        Ok(content)
    }

    /// A message of the peer's next chain, the first received from it, which steps the DH-root
    /// ratchet (and the optional PQ KEM ratchet).
    fn receive_next_chain(
        &mut self,
        header: &Header,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        // The peer's previous chain cannot be shorter than what was received from it.
        if header.previous_chain_length < self.message_number_receiver {
            return Err(ErrorKind::InvalidHeader.into());
        }
        check_skip_count(
            (header.previous_chain_length - self.message_number_receiver)
                .saturating_add(header.message_number),
        )?;
        let next_message_number_receiver = header
            .message_number
            .checked_add(1)
            .ok_or(ErrorKind::InvalidHeader)?;

        let mut tx = RatchetTx::begin(self);
        let prev_recv_hk = tx.ratchet.header_key_receiver();
        let skipped_previous = skip_message_keys(
            &mut tx.ratchet,
            tx.party.message_number_receiver,
            header.previous_chain_length,
        )?;

        let kem_secrets = tx.kem.receive_chain_step(header)?;
        tx.ratchet
            .step_dh_root_with(&header.public_key, kem_secrets.recv())
            .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;
        tx.ratchet
            .step_dh_root_with(&header.public_key, kem_secrets.send())
            .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;

        let skipped_next = skip_message_keys(&mut tx.ratchet, 0, header.message_number)?;
        let message_key = tx
            .ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        let content = open_content(&tx.party.associated_data, &message_key, message)?;

        // Commit BOTH ratchets only after content AEAD succeeds.
        let new_recv_hk = tx.ratchet.header_key_receiver();
        tx.commit();
        self.skipped_message_keys.extend(skipped_previous);
        if let Some(prev_hk) = prev_recv_hk.as_ref() {
            self.skipped_message_keys
                .attach_evicted(prev_hk, &self.current_chain_evicted);
        }
        self.skipped_message_keys.next_chain();
        self.current_chain_evicted.clear();
        self.skipped_message_keys
            .extend_with_evictions(skipped_next, |evicted_hk, msg_num| {
                if new_recv_hk
                    .as_ref()
                    .is_some_and(|cur| bool::from(cur.ct_eq(evicted_hk)))
                {
                    self.current_chain_evicted.insert(msg_num);
                }
            });
        self.previous_chain_length = self.message_number_sender;
        self.message_number_sender = 0;
        self.message_number_receiver = next_message_number_receiver;
        Ok(content)
    }

    /// Decrypt the header with `header_key`; None if it is not the key of this header.
    fn open_header(
        &self,
        header_key: &HeaderKey,
        message: &EncryptedMessage,
    ) -> Option<Result<Header>> {
        let header = Zeroizing::new(
            decrypt(
                header_key,
                HEADER_INFO,
                &self.associated_data,
                &message.header,
            )
            .ok()?,
        );
        Some(Header::decode(header.as_slice()).map_err(|e| Error::new(ErrorKind::InvalidHeader, e)))
    }

    /// Validate all party invariants on deserialization.
    #[cfg(any(feature = "serde", feature = "prost"))]
    fn validate(&self) -> Result<()> {
        let receiver_header_key = self.ratchet.header_key_receiver();
        let next_receiver_header_key = self.ratchet.next_header_key_receiver();
        if self.ratchet.dh_step_updates_sender()
            || (self.ratchet.header_key_sender().is_none()
                && (self.message_number_sender != 0 || self.previous_chain_length != 0))
            || (receiver_header_key.is_none()
                && (self.message_number_receiver != 0
                    || !self.skipped_message_keys.is_empty()
                    || !self.current_chain_evicted.is_empty()))
        {
            return Err(ErrorKind::MalformedState.into());
        }
        self.current_chain_evicted
            .validate(Some(self.message_number_receiver))?;
        self.skipped_message_keys.validate(
            receiver_header_key
                .as_deref()
                .map(|key| (key, self.message_number_receiver)),
            Some(&*next_receiver_header_key),
        )
    }
}

/// Decrypt the content with `message_key`; it only authenticates with the encrypted header it was
/// sent with.
fn open_content(
    associated_data: &[u8],
    message_key: &MessageKey,
    message: &EncryptedMessage,
) -> Result<Vec<u8>> {
    decrypt(
        message_key,
        CONTENT_INFO,
        &content_associated_data(associated_data, &message.header),
        &message.content,
    )
    .map_err(|e| Error::new(ErrorKind::Undecryptable, e))
}

#[cfg(feature = "prost")]
impl From<&Party> for crate::proto::Party {
    fn from(party: &Party) -> Self {
        let (current_chain_evicted, current_chain_evicted_below) =
            party.current_chain_evicted.to_proto();
        Self {
            ratchet: Some((&party.ratchet).into()),
            skipped_chains: party.skipped_message_keys.to_proto(),
            previous_chain_length: party.previous_chain_length,
            message_number_sender: party.message_number_sender,
            message_number_receiver: party.message_number_receiver,
            associated_data: party.associated_data.clone(),
            current_chain_evicted,
            current_chain_evicted_below,
            kem_ratchet: party.kem_ratchet.to_proto(),
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&crate::proto::Party> for Party {
    type Error = Error;

    fn try_from(party: &crate::proto::Party) -> Result<Self> {
        let ratchet = party.ratchet.as_ref().ok_or(ErrorKind::MalformedState)?;
        let kem_ratchet = KemState::from_proto(party.kem_ratchet.as_ref())?;
        let restored = Self {
            ratchet: Ratchet::try_from(ratchet)
                .map_err(|e| Error::new(ErrorKind::MalformedState, e))?,
            skipped_message_keys: SkippedKeys::from_proto(&party.skipped_chains)?,
            previous_chain_length: party.previous_chain_length,
            message_number_sender: party.message_number_sender,
            message_number_receiver: party.message_number_receiver,
            associated_data: party.associated_data.clone(),
            current_chain_evicted: EvictedSet::from_proto(
                &party.current_chain_evicted,
                party.current_chain_evicted_below,
            )?,
            kem_ratchet,
        };
        restored.validate()?;
        Ok(restored)
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

/// Fails if receiving a message would skip more than [`SKIP_MAX`] message keys.
fn check_skip_count(count: u64) -> Result<()> {
    if count > SKIP_MAX {
        return Err(ErrorKind::TooManySkipped.into());
    }
    Ok(())
}

/// Step `ratchet`'s receiving chain from index `from` up to `until`, collecting the message keys;
/// None if there are none to skip.
fn skip_message_keys(ratchet: &mut Ratchet, from: u64, until: u64) -> Result<Option<SkippedChain>> {
    if from >= until {
        return Ok(None);
    }
    let header_key = ratchet
        .header_key_receiver()
        .ok_or(ErrorKind::InvalidHeader)?;
    let mut skipped = SkippedChain::new(header_key);
    for message_number in from..until {
        let message_key = ratchet
            .step_message_ratchet_receiver()
            .ok_or(ErrorKind::InvalidHeader)?;
        skipped.insert(message_number, message_key);
    }
    Ok(Some(skipped))
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

/// Per-encryption AEAD key, nonce, and HMAC key derived from a message or header key; zeroized on
/// drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKeys {
    encryption_key: [u8; ENCRYPTION_KEY_LEN],
    gcm_nonce: [u8; GCM_NONCE_LEN],
    authentication_key: [u8; HASH_LEN],
}

/// HKDF-SHA256 of `key`, with `info` and the encryption's `nonce` as info: the AES-256-GCM key
/// and nonce, then the HMAC-SHA256 key.
fn derive_keys(key: &[u8], info: &[u8], nonce: &[u8; NONCE_LEN]) -> DerivedKeys {
    let mut keys = Zeroizing::new([0; ENCRYPTION_KEY_LEN + GCM_NONCE_LEN + HASH_LEN]);
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(&[0; HASH_LEN]), key);
    prk.zeroize();
    hkdf.expand_multi_info(&[info, nonce], keys.as_mut_slice())
        .expect("the keys are a valid HKDF-SHA256 output length");
    let (encryption_key, rest) = keys.split_at(ENCRYPTION_KEY_LEN);
    let (gcm_nonce, authentication_key) = rest.split_at(GCM_NONCE_LEN);
    DerivedKeys {
        encryption_key: encryption_key.try_into().unwrap(),
        gcm_nonce: gcm_nonce.try_into().unwrap(),
        authentication_key: authentication_key.try_into().unwrap(),
    }
}

/// Encrypt to `nonce || AES-256-GCM ciphertext || HMAC-SHA256(aad || nonce || ciphertext)`.
///
/// A header key encrypts every header of its chain, so AES-GCM must never see one key and nonce
/// twice. Each call draws a random 256-bit nonce and derives the AES-GCM key and nonce from `key`
/// and it: two calls only share them if they draw the same nonce, and there is no counter to
/// keep, persist or roll back.
fn encrypt(
    key: &[u8; KEY_LENGTH],
    info: &[u8],
    aad: &[u8],
    content: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError)?;
    let keys = derive_keys(key, info, &nonce);

    let mut out = nonce.to_vec();
    out.extend(
        Aes256Gcm::new(&keys.encryption_key.into())
            .encrypt(&keys.gcm_nonce.into(), Payload { msg: content, aad })
            .map_err(|_| CryptoError)?,
    );

    let mut hmac = Hmac::<Sha256>::new_from_slice(&keys.authentication_key).unwrap();
    hmac.update(aad);
    hmac.update(&out);
    out.extend(hmac.finalize().into_bytes());
    Ok(out)
}

fn decrypt(
    key: &[u8; KEY_LENGTH],
    info: &[u8],
    aad: &[u8],
    encrypted: &[u8],
) -> core::result::Result<Vec<u8>, CryptoError> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let (nonce_and_ciphertext, tag) = encrypted.split_at(encrypted.len() - TAG_LEN);
    let (nonce, ciphertext) = nonce_and_ciphertext.split_at(NONCE_LEN);
    let keys = derive_keys(key, info, nonce.try_into().unwrap());

    let mut hmac = Hmac::<Sha256>::new_from_slice(&keys.authentication_key).unwrap();
    hmac.update(aad);
    hmac.update(nonce_and_ciphertext);
    hmac.verify_slice(tag).map_err(|_| CryptoError)?;

    Aes256Gcm::new(&keys.encryption_key.into())
        .decrypt(
            &keys.gcm_nonce.into(),
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
        let bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();
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
            party.current_chain_evicted.clone(),
            party.kem_ratchet.test_snapshot(),
        )
    }

    /// `message` with its header decrypted, `alter`ed and encrypted again, by someone who has
    /// the header key but not the message key.
    fn reencrypt_header(
        receiver: &Party,
        header_key: &HeaderKey,
        message: &EncryptedMessage,
        alter: impl FnOnce(&mut Header),
    ) -> EncryptedMessage {
        let mut header = receiver.open_header(header_key, message).unwrap().unwrap();
        alter(&mut header);
        let header = encrypt(
            header_key,
            HEADER_INFO,
            &receiver.associated_data,
            &header.encode_to_vec(),
        )
        .unwrap();
        EncryptedMessage {
            header: header.into(),
            content: message.content.clone(),
        }
    }

    #[test]
    fn bob_sends_only_after_receiving() {
        let (mut alice, mut bob) = session();
        assert!(!alice.is_pq_ratchet_active());
        assert!(!bob.is_pq_ratchet_active());
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
    fn encrypt_counter_overflow_does_not_burn_state() {
        let (mut alice, _bob) = session();
        alice.message_number_sender = u64::MAX;
        let before = state(&alice);
        assert_eq!(
            alice.encrypt(b"overflow").unwrap_err().kind(),
            ErrorKind::Crypto
        );
        assert_eq!(state(&alice), before);
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
        assert_eq!(bob.skipped_message_keys.header_keys().count(), 0);
        assert_eq!(
            bob.decrypt(&sent[0]).unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
        // The duplicate changed nothing.
        let message = alice.encrypt(b"m3").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"m3");
    }

    #[test]
    fn evicted_skipped_key_is_distinguished_from_duplicate() {
        let (mut alice, mut bob) = session();
        let evicted_msg = alice.encrypt(b"evicted-0").unwrap();
        let mut remaining_skipped = Vec::new();
        for i in 1..SKIP_MAX {
            remaining_skipped.push(alice.encrypt(format!("lost-{i}").as_bytes()).unwrap());
        }
        let m_pivot = alice.encrypt(b"pivot").unwrap();
        assert_eq!(bob.decrypt(&m_pivot).unwrap(), b"pivot");
        assert_eq!(bob.skipped_message_keys.len(), SKIP_MAX);

        // One more skipped message forces eviction of message 0.
        let delayed = alice.encrypt(b"delayed").unwrap();
        let m_after = alice.encrypt(b"after").unwrap();
        assert_eq!(bob.decrypt(&m_after).unwrap(), b"after");

        // Message 0 was evicted (never received): MUST report EvictedMessage, NOT DuplicateMessage.
        assert_eq!(
            bob.decrypt(&evicted_msg).unwrap_err().kind(),
            ErrorKind::EvictedMessage
        );
        // m_pivot WAS received: MUST still report DuplicateMessage.
        assert_eq!(
            bob.decrypt(&m_pivot).unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
        // Delayed message decrypts, then replays as DuplicateMessage.
        assert_eq!(bob.decrypt(&delayed).unwrap(), b"delayed");
        assert_eq!(
            bob.decrypt(&delayed).unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );

        // Even after every remaining skipped key on this chain is consumed (so SkippedKeys is
        // empty), message 0 STILL reports EvictedMessage!
        for msg in &remaining_skipped {
            bob.decrypt(msg).unwrap();
        }
        assert_eq!(bob.skipped_message_keys.len(), 0);
        assert_eq!(
            bob.decrypt(&evicted_msg).unwrap_err().kind(),
            ErrorKind::EvictedMessage
        );
        assert_eq!(
            bob.decrypt(&m_pivot).unwrap_err().kind(),
            ErrorKind::DuplicateMessage
        );
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
    fn lost_messages_do_not_block_later_ones() {
        let (mut alice, mut bob) = session();
        // The keys of SKIP_MAX lost messages fill Bob's room for skipped keys.
        for _ in 0..SKIP_MAX {
            alice.encrypt(b"lost").unwrap();
        }
        let message = alice.encrypt(b"m").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"m");
        assert_eq!(bob.skipped_message_keys.len(), SKIP_MAX);

        // After another gap, the oldest keys make room instead of the message being rejected.
        let delayed = alice.encrypt(b"delayed").unwrap();
        alice.encrypt(b"lost").unwrap();
        let message = alice.encrypt(b"after a gap").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"after a gap");
        assert_eq!(bob.skipped_message_keys.len(), SKIP_MAX);
        assert_eq!(bob.decrypt(&delayed).unwrap(), b"delayed");
    }

    /// Bob sends a message to Alice, and Alice one to Bob: each moves on to the other's next
    /// chain.
    fn round_trip(alice: &mut Party, bob: &mut Party) {
        let message = bob.encrypt(b"b").unwrap();
        assert_eq!(alice.decrypt(&message).unwrap(), b"b");
        let message = alice.encrypt(b"a").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"a");
    }

    #[test]
    fn skipped_keys_go_after_max_skipped_chains() {
        let (mut alice, mut bob) = session();
        let delayed: Vec<_> = ["d0", "d1"]
            .into_iter()
            .map(|content| alice.encrypt(content.as_bytes()).unwrap())
            .collect();
        let message = alice.encrypt(b"m").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"m");

        for _ in 1..MAX_SKIPPED_CHAINS {
            round_trip(&mut alice, &mut bob);
        }
        // Alice's first chain is the oldest of her last MAX_SKIPPED_CHAINS.
        assert_eq!(bob.decrypt(&delayed[0]).unwrap(), b"d0");
        round_trip(&mut alice, &mut bob);
        assert_eq!(
            bob.decrypt(&delayed[1]).unwrap_err().kind(),
            ErrorKind::Undecryptable
        );
        assert_eq!(bob.skipped_message_keys.len(), 0);
    }

    #[test]
    fn out_of_range_counter_is_rejected() {
        let (alice, mut bob) = session();
        // A message made from Alice's state, whose header claims u64::MAX earlier messages.
        let mut sender = alice.ratchet.clone();
        let header = Header {
            public_key: Bytes::copy_from_slice(&sender.public_key()),
            previous_chain_length: 0,
            message_number: u64::MAX,
            pq_suite: None,
            pq_public_key: None,
            pq_ciphertext: None,
            pq_key_id: None,
        };
        let header = encrypt(
            &sender.header_key_sender().unwrap(),
            HEADER_INFO,
            b"AD",
            &header.encode_to_vec(),
        )
        .unwrap();
        let content = encrypt(
            &sender.step_message_ratchet_sender().unwrap(),
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
        let forged = reencrypt_header(&bob, &header_key, &next, |header| {
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
            reencrypt_header(&bob, &header_key, &sent[0], |_| {}),
            reencrypt_header(&bob, &header_key, &sent[3], |header| {
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
    fn classical_session_emits_zero_pq_fields_and_rejects_unexpected_pq_header() {
        let (mut alice, mut bob) = session();
        let msg = alice.encrypt(b"classic").unwrap();
        // Decrypt header to verify all PQ fields are None.
        let hk = bob.ratchet.next_header_key_receiver();
        let header = bob.open_header(&hk, &msg).unwrap().unwrap();
        assert_eq!(header.pq_suite, None);
        assert_eq!(header.pq_public_key, None);
        assert_eq!(header.pq_ciphertext, None);
        assert_eq!(header.pq_key_id, None);

        // Injecting PQ fields into a classical header fails closed.
        let forged = reencrypt_header(&bob, &hk, &msg, |h| {
            h.pq_suite = Some(1);
        });
        assert_eq!(
            bob.decrypt(&forged).unwrap_err().kind(),
            ErrorKind::InvalidHeader
        );
        // Original classical message still decrypts cleanly.
        assert_eq!(bob.decrypt(&msg).unwrap(), b"classic");
    }

    /// `party` saved and restored, once through each format enabled.
    #[cfg(any(feature = "prost", feature = "serde"))]
    fn restored(party: &Party) -> Vec<Party> {
        Vec::from([
            #[cfg(feature = "prost")]
            Party::try_from(&crate::proto::Party::from(party)).unwrap(),
            #[cfg(feature = "serde")]
            serde_json::from_str(&serde_json::to_string(party).unwrap()).unwrap(),
        ])
    }

    #[test]
    #[cfg(any(feature = "prost", feature = "serde"))]
    fn restored_parties_carry_on() {
        let (mut alice, mut bob) = session();
        let delayed = alice.encrypt(b"delayed").unwrap();
        let message = alice.encrypt(b"m").unwrap();
        assert_eq!(bob.decrypt(&message).unwrap(), b"m");
        let reply = bob.encrypt(b"reply").unwrap();

        let before = state(&bob);
        for (mut alice, mut bob) in restored(&alice).into_iter().zip(restored(&bob)) {
            assert_eq!(state(&bob), before);
            // The skipped key, the receiving chain, then the sending chains and DH steps.
            assert_eq!(bob.decrypt(&delayed).unwrap(), b"delayed");
            assert_eq!(alice.decrypt(&reply).unwrap(), b"reply");
            round_trip(&mut alice, &mut bob);
        }
    }

    #[test]
    #[cfg(any(feature = "prost", feature = "serde"))]
    fn rejects_malformed_deserialized_party_states() {
        let (_alice, bob) = session();

        #[cfg(feature = "prost")]
        {
            // Bob has no sending chain yet, so non-zero message_number_sender is invalid.
            let mut bad = crate::proto::Party::from(&bob);
            bad.message_number_sender = 1;
            assert_eq!(
                Party::try_from(&bad).unwrap_err().kind(),
                ErrorKind::MalformedState
            );

            // Exceeding MAX_SKIPPED_CHAINS is rejected.
            let mut bad_chains = crate::proto::Party::from(&bob);
            for i in 0..=(MAX_SKIPPED_CHAINS as u8) {
                bad_chains.skipped_chains.push(crate::proto::SkippedChain {
                    header_key: vec![i; 32],
                    message_keys: vec![crate::proto::MessageKey {
                        message_number: 0,
                        key: vec![i; 32],
                    }],
                    age: 0,
                    evicted: vec![],
                    evicted_below: 0,
                });
            }
            assert_eq!(
                Party::try_from(&bad_chains).unwrap_err().kind(),
                ErrorKind::MalformedState
            );

            // Exceeding SKIP_MAX is rejected before allocation.
            let mut bad_keys = crate::proto::Party::from(&bob);
            bad_keys.skipped_chains.push(crate::proto::SkippedChain {
                header_key: vec![9; 32],
                message_keys: (0..=SKIP_MAX)
                    .map(|n| crate::proto::MessageKey {
                        message_number: n,
                        key: vec![1; 32],
                    })
                    .collect(),
                age: 0,
                evicted: vec![],
                evicted_below: 0,
            });
            assert_eq!(
                Party::try_from(&bad_keys).unwrap_err().kind(),
                ErrorKind::MalformedState
            );
        }

        #[cfg(feature = "serde")]
        {
            let mut val: serde_json::Value =
                serde_json::from_str(&serde_json::to_string(&bob).unwrap()).unwrap();
            val["message_number_receiver"] = serde_json::json!(5);
            assert!(serde_json::from_value::<Party>(val).is_err());

            #[cfg(not(has_pq))]
            {
                // Non-PQ build MUST fail closed if serde JSON contains a non-null `kem_ratchet`.
                let mut with_pq: serde_json::Value =
                    serde_json::from_str(&serde_json::to_string(&bob).unwrap()).unwrap();
                with_pq["kem_ratchet"] = serde_json::json!({"suite": "MlKem1024"});
                assert!(serde_json::from_value::<Party>(with_pq).is_err());

                // Explicit null `kem_ratchet` (a classical party serialized by a PQ build) loads OK.
                let mut with_null: serde_json::Value =
                    serde_json::from_str(&serde_json::to_string(&bob).unwrap()).unwrap();
                with_null["kem_ratchet"] = serde_json::Value::Null;
                assert!(serde_json::from_value::<Party>(with_null).is_ok());
            }
        }

        #[cfg(all(feature = "prost", not(has_pq)))]
        {
            // Non-PQ build MUST fail closed if protobuf state contains `kem_ratchet`.
            let mut with_pq = crate::proto::Party::from(&bob);
            let mut kem = ratchetx2::proto::KemRatchet::default();
            kem.suite = 1;
            with_pq.kem_ratchet = Some(kem);
            assert_eq!(
                Party::try_from(&with_pq).unwrap_err().kind(),
                ErrorKind::MalformedState
            );
        }
    }

    #[cfg(any(feature = "serde", feature = "prost"))]
    #[test]
    fn party_rejects_a_ratchet_between_dh_steps() {
        let (alice, mut bob) = session();
        bob.ratchet
            .step_dh_root(&alice.ratchet.public_key())
            .unwrap();
        assert!(bob.ratchet.dh_step_updates_sender());
        #[cfg(feature = "serde")]
        {
            assert!(serde_json::from_str::<Party>(&serde_json::to_string(&bob).unwrap()).is_err());
            assert!(postcard::from_bytes::<Party>(&postcard::to_allocvec(&bob).unwrap()).is_err());
        }
        #[cfg(feature = "prost")]
        {
            let bytes = crate::proto::Party::from(&bob).encode_to_vec();
            let raw = crate::proto::Party::decode(bytes.as_slice()).unwrap();
            assert_eq!(
                Party::try_from(&raw).unwrap_err().kind(),
                ErrorKind::MalformedState
            );
        }
    }

    #[test]
    fn ratchet_tx_drop_leaves_party_unchanged() {
        let (mut alice, mut bob) = session();
        let before = state(&alice);
        {
            let mut tx = RatchetTx::begin(&mut alice);
            let _ = tx.ratchet.step_message_ratchet_sender().unwrap();
            let _ = tx.kem.prepare_send().unwrap();
            // Drop without calling `tx.commit()`.
        }
        assert_eq!(state(&alice), before);
        let msg = alice.encrypt(b"still-in-sync").unwrap();
        assert_eq!(bob.decrypt(&msg).unwrap(), b"still-in-sync");
    }

    #[test]
    fn associated_data_accessor_matches_input() {
        let (alice, bob) = session();
        assert_eq!(alice.associated_data(), b"AD");
        assert_eq!(bob.associated_data(), b"AD");

        let keys = SharedKeys {
            secret_key: [4; 32],
            header_key_alice: [5; 32],
            header_key_bob: [6; 32],
        };
        let custom_ad = [0xABu8; 96];
        let custom_bob = Party::new(Ratchet::bob(&keys, DhPrivateKey::generate()), custom_ad);
        assert_eq!(custom_bob.associated_data(), &custom_ad);
        assert_eq!(custom_bob.pq_suite_id(), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn postcard_preserves_skipped_and_evicted_keys() {
        // Populate skipped keys AND current-chain evictions so every nested struct is exercised.
        let (mut alice, mut bob) = session();
        let evicted_msg = alice.encrypt(b"evicted-0").unwrap();
        for i in 1..SKIP_MAX {
            alice.encrypt(format!("lost-{i}").as_bytes()).unwrap();
        }
        let pivot = alice.encrypt(b"pivot").unwrap();
        assert_eq!(bob.decrypt(&pivot).unwrap(), b"pivot");
        let delayed = alice.encrypt(b"delayed").unwrap();
        let after = alice.encrypt(b"after").unwrap();
        assert_eq!(bob.decrypt(&after).unwrap(), b"after");

        // Standalone positional roundtrip.
        let before = state(&bob);
        let v1 = postcard::to_allocvec(&(
            &bob.ratchet,
            &bob.skipped_message_keys,
            bob.previous_chain_length,
            bob.message_number_sender,
            bob.message_number_receiver,
            &bob.associated_data,
            &bob.current_chain_evicted,
        ))
        .unwrap();
        let follow_up = alice.encrypt(b"follow-up").unwrap();
        for mut restored in [
            postcard::from_bytes(&postcard::to_allocvec(&bob).unwrap()).unwrap(),
            postcard::from_bytes::<LegacyPartyV1>(&v1)
                .unwrap()
                .into_party(),
        ] {
            assert_eq!(state(&restored), before);
            assert_eq!(restored.decrypt(&delayed).unwrap(), b"delayed");
            assert_eq!(
                restored.decrypt(&evicted_msg).unwrap_err().kind(),
                ErrorKind::EvictedMessage
            );
            assert_eq!(restored.decrypt(&follow_up).unwrap(), b"follow-up");
        }

        // Nested positional roundtrip `(Party, u8)` mimicking `SessionState::Active { party, id, .. }`
        // across tags 0 (Option::None), 1 (Option::Some), 2 and 0xFF (invalid Option discriminants).
        for trailing_tag in [0u8, 1u8, 2u8, 0xFFu8] {
            let (restored_party, restored_tag): (Party, u8) =
                postcard::from_bytes(&postcard::to_allocvec(&(&bob, trailing_tag)).unwrap())
                    .unwrap();
            assert_eq!(restored_tag, trailing_tag);
            assert_eq!(state(&restored_party), before);
        }
    }

    #[cfg(has_pq)]
    mod pq_tests {
        use super::*;

        fn enabled_suites() -> Vec<PqSuite> {
            vec![
                #[cfg(feature = "ml-kem-1024")]
                PqSuite::MlKem1024,
                #[cfg(feature = "ml-kem-768")]
                PqSuite::MlKem768,
            ]
        }

        fn pq_session(suite: PqSuite, config: KemRatchetConfig) -> (Party, Party) {
            let keys = SharedKeys {
                secret_key: [11; 32],
                header_key_alice: [12; 32],
                header_key_bob: [13; 32],
            };
            let bob = Ratchet::bob(&keys, DhPrivateKey::generate());
            let alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();
            (
                Party::new_pq_with_config(alice, "AD-PQ", suite, config),
                Party::new_pq_with_config(bob, "AD-PQ", suite, config),
            )
        }

        #[test]
        fn pq_back_and_forth_default_and_every_turn_under_8kib() {
            for suite in enabled_suites() {
                for config in [KemRatchetConfig::default(), KemRatchetConfig::every_turn()] {
                    let (mut alice, mut bob) = pq_session(suite, config);
                    assert_eq!(alice.pq_suite(), Some(suite));
                    assert!(alice.is_pq_ratchet_active());

                    for round in 0..12 {
                        let a_msg = alice.encrypt(format!("alice-{round}").as_bytes()).unwrap();
                        // Encrypted header MUST stay well under 8 KiB (even under 4 KiB).
                        assert!(
                            a_msg.header.len() < 4096,
                            "header too large: {} bytes",
                            a_msg.header.len()
                        );
                        assert_eq!(
                            bob.decrypt(&a_msg).unwrap(),
                            format!("alice-{round}").as_bytes()
                        );

                        let b_msg = bob.encrypt(format!("bob-{round}").as_bytes()).unwrap();
                        assert!(
                            b_msg.header.len() < 4096,
                            "header too large: {} bytes",
                            b_msg.header.len()
                        );
                        assert_eq!(
                            alice.decrypt(&b_msg).unwrap(),
                            format!("bob-{round}").as_bytes()
                        );
                    }
                }
            }
        }

        #[test]
        fn pq_crossed_simultaneous_offers_resolve_cleanly() {
            for suite in enabled_suites() {
                let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::default());
                // Establish session first.
                let a0 = alice.encrypt(b"a0").unwrap();
                assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");
                let b0 = bob.encrypt(b"b0").unwrap();
                assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");

                // Force simultaneous offers on BOTH sides before either receives the other!
                alice.kem_ratchet.as_mut().unwrap().force_rekey().unwrap();
                bob.kem_ratchet.as_mut().unwrap().force_rekey().unwrap();

                // Both send concurrently: Alice on a new chain, Bob on his current chain.
                let a1 = alice.encrypt(b"a1-offer").unwrap();
                let b1 = bob.encrypt(b"b1-offer").unwrap();

                // Deliver both crossed messages!
                assert_eq!(alice.decrypt(&b1).unwrap(), b"b1-offer");
                assert_eq!(bob.decrypt(&a1).unwrap(), b"a1-offer");

                // Continue exchanging messages: both crossed offers complete cleanly.
                let b2 = bob.encrypt(b"b2").unwrap();
                assert_eq!(alice.decrypt(&b2).unwrap(), b"b2");
                let a2 = alice.encrypt(b"a2").unwrap();
                assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
                let b3 = bob.encrypt(b"b3").unwrap();
                assert_eq!(alice.decrypt(&b3).unwrap(), b"b3");

                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 0);
                assert_eq!(bob.kem_ratchet.as_ref().unwrap().pending_offer_count(), 0);
            }
        }

        #[test]
        fn pq_out_of_order_skipped_and_lost_messages_across_epochs() {
            for suite in enabled_suites() {
                let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::every_turn());

                // Alice sends 3 messages on Chain 0 (all carry ek_A0). Drop a0, delay a1, deliver a2!
                let _a0_lost = alice.encrypt(b"a0-lost").unwrap();
                let a1_delayed = alice.encrypt(b"a1-delayed").unwrap();
                let a2 = alice.encrypt(b"a2").unwrap();
                assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");

                // Bob sends 3 messages on Chain 0 (all carry ct_A0 + ek_B0). Drop b0, delay b1, deliver b2!
                let _b0_lost = bob.encrypt(b"b0-lost").unwrap();
                let b1_delayed = bob.encrypt(b"b1-delayed").unwrap();
                let b2 = bob.encrypt(b"b2").unwrap();
                assert_eq!(alice.decrypt(&b2).unwrap(), b"b2");

                // Advance 2 more KEM epochs.
                for i in 0..2 {
                    let a = alice.encrypt(format!("epoch-a-{i}").as_bytes()).unwrap();
                    assert_eq!(bob.decrypt(&a).unwrap(), format!("epoch-a-{i}").as_bytes());
                    let b = bob.encrypt(format!("epoch-b-{i}").as_bytes()).unwrap();
                    assert_eq!(
                        alice.decrypt(&b).unwrap(),
                        format!("epoch-b-{i}").as_bytes()
                    );
                }

                // Delayed messages from earlier KEM epochs STILL decrypt cleanly!
                assert_eq!(bob.decrypt(&a1_delayed).unwrap(), b"a1-delayed");
                assert_eq!(alice.decrypt(&b1_delayed).unwrap(), b"b1-delayed");
                // Replaying an earlier-epoch consumed message while that chain still has another
                // skipped key (`a0_lost`) MUST report DuplicateMessage (not Undecryptable).
                assert_eq!(
                    bob.decrypt(&a1_delayed).unwrap_err().kind(),
                    ErrorKind::DuplicateMessage
                );
                // Replaying a current-epoch message is rejected as DuplicateMessage.
                let a_cur = alice.encrypt(b"current-epoch").unwrap();
                assert_eq!(bob.decrypt(&a_cur).unwrap(), b"current-epoch");
                assert_eq!(
                    bob.decrypt(&a_cur).unwrap_err().kind(),
                    ErrorKind::DuplicateMessage
                );
            }
        }

        #[test]
        fn pq_delayed_evicted_offer_never_breaks_session_and_mid_chain_ct_mismatch_rejected() {
            for suite in enabled_suites() {
                // Case 1 (pending fresher offer present) and Case 2 (post-encapsulation `None`
                // pending slot): peer creates E1 on a delayed message, calls `force_rekey` x4
                // (evicting E1 from MAX_PENDING_OFFERS = 4), then delayed message carrying E1
                // arrives out of order. Neither case may overwrite/adopt evicted E1, and replies
                // MUST continue round-tripping cleanly.
                for reply_before_delayed in [false, true] {
                    let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::default());
                    let a0 = alice.encrypt(b"a0").unwrap();
                    assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");
                    let b0 = bob.encrypt(b"b0").unwrap();
                    assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");

                    // Alice starts a new chain with E1 on a delayed message, then calls
                    // `force_rekey` x4 so E1 is evicted from Alice's `pending_offers` ring!
                    let a_lead = alice.encrypt(b"a-lead").unwrap();
                    assert_eq!(bob.decrypt(&a_lead).unwrap(), b"a-lead");

                    let evicted_id = alice.kem_ratchet.as_mut().unwrap().force_rekey().unwrap();
                    let a_delayed_e1 = alice.encrypt(b"a-delayed-e1").unwrap();
                    let mut latest_id = evicted_id;
                    for _ in 0..ratchetx2::pq::MAX_PENDING_OFFERS {
                        latest_id = alice.kem_ratchet.as_mut().unwrap().force_rekey().unwrap();
                    }
                    assert_ne!(evicted_id, latest_id);
                    let a_latest = alice.encrypt(b"a-latest-e5").unwrap();
                    // Bob receives `a_latest` (queuing `latest_id` via `receive_current_chain`).
                    assert_eq!(bob.decrypt(&a_latest).unwrap(), b"a-latest-e5");

                    if reply_before_delayed {
                        // Advance through a turn so Bob consumes `latest_id` and `peer_pending_ek`
                        // becomes `None` BEFORE `a_delayed_e1` arrives out of order!
                        let b1 = bob.encrypt(b"b1").unwrap();
                        assert_eq!(alice.decrypt(&b1).unwrap(), b"b1");
                        let a_turn2 = alice.encrypt(b"a-turn2").unwrap();
                        assert_eq!(bob.decrypt(&a_turn2).unwrap(), b"a-turn2");
                        let b2 = bob.encrypt(b"b2").unwrap();
                        assert_eq!(alice.decrypt(&b2).unwrap(), b"b2");
                    }

                    // Now delayed `a_delayed_e1` (carrying evicted E1) arrives out of order!
                    assert_eq!(bob.decrypt(&a_delayed_e1).unwrap(), b"a-delayed-e1");

                    // Round-trip replies MUST still succeed (never encapsulating evicted E1)!
                    for turn in 0..2 {
                        let a_msg = alice.encrypt(format!("after-a-{turn}").as_bytes()).unwrap();
                        assert_eq!(
                            bob.decrypt(&a_msg).unwrap(),
                            format!("after-a-{turn}").as_bytes()
                        );
                        let b_msg = bob.encrypt(format!("after-b-{turn}").as_bytes()).unwrap();
                        assert_eq!(
                            alice.decrypt(&b_msg).unwrap(),
                            format!("after-b-{turn}").as_bytes()
                        );
                    }
                }

                // Mid-chain ct/ek_id mismatch on current chain is rejected.
                let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::every_turn());
                let a0 = alice.encrypt(b"a0").unwrap();
                assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");
                let b0 = bob.encrypt(b"b0").unwrap();
                assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");
                let b_follow = bob.encrypt(b"b-follow").unwrap();
                let alice_cur_hk = alice.ratchet.header_key_receiver().unwrap();
                let forged = reencrypt_header(&alice, &alice_cur_hk, &b_follow, |h| {
                    h.pq_key_id = Some(Bytes::from_static(&[0xEE; KEM_KEY_ID_LENGTH]));
                });
                assert_eq!(
                    alice.decrypt(&forged).unwrap_err().kind(),
                    ErrorKind::InvalidHeader
                );
                assert_eq!(alice.decrypt(&b_follow).unwrap(), b"b-follow");
            }
        }

        #[test]
        fn enable_pq_ratchet_is_idempotent_and_rejects_suite_change() {
            for suite in enabled_suites() {
                let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::default());
                // Alice sends A0 carrying an active offer ek_A0; Bob responds with ct_A0.
                let a0 = alice.encrypt(b"a0").unwrap();
                assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");
                let b0 = bob.encrypt(b"b0").unwrap();
                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 1);

                // Re-enabling the same suite MUST be a no-op (preserving pending offer seeds).
                alice.enable_pq_ratchet(suite).unwrap();
                alice
                    .enable_pq_ratchet_with_config(suite, KemRatchetConfig::every_turn())
                    .unwrap();
                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 1);

                // Switching to a different PQ suite MUST fail without dropping pending offers.
                #[cfg(all(feature = "ml-kem-1024", feature = "ml-kem-768"))]
                {
                    let other = match suite {
                        PqSuite::MlKem1024 => PqSuite::MlKem768,
                        PqSuite::MlKem768 => PqSuite::MlKem1024,
                        _ => unreachable!(),
                    };
                    assert_eq!(
                        alice.enable_pq_ratchet(other).unwrap_err().kind(),
                        ErrorKind::Crypto
                    );
                    assert_eq!(alice.pq_suite(), Some(suite));
                    assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 1);
                }

                // Bob's in-flight ct_A0 MUST still decapsulate and decrypt cleanly!
                assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");
                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 0);
            }
        }

        #[test]
        fn pq_tampered_message_leaves_both_ratchets_unchanged() {
            for suite in enabled_suites() {
                let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::every_turn());
                let a0 = alice.encrypt(b"a0").unwrap();
                assert_eq!(bob.decrypt(&a0).unwrap(), b"a0");
                let b0 = bob.encrypt(b"b0").unwrap();

                // Tamper with body ciphertext: Alice MUST NOT consume her pending KEM offer!
                let mut tampered_body = b0.clone();
                let mut content = tampered_body.content.to_vec();
                content[0] ^= 0xFF;
                tampered_body.content = content.into();

                let before = state(&alice);
                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 1);
                assert_eq!(
                    alice.decrypt(&tampered_body).unwrap_err().kind(),
                    ErrorKind::Undecryptable
                );
                assert_eq!(state(&alice), before);
                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 1);

                // Authentic b0 still decrypts and consumes the offer on commit.
                assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");
                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 0);
            }
        }

        #[test]
        fn pq_ratchet_tx_drop_leaves_party_and_kem_unchanged() {
            for suite in enabled_suites() {
                let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::every_turn());
                let before = state(&alice);
                {
                    let mut tx = RatchetTx::begin(&mut alice);
                    let _ = tx.ratchet.step_message_ratchet_sender().unwrap();
                    let header = tx.kem.prepare_send().unwrap();
                    assert!(header.pq_public_key.is_some());
                    // Drop without calling `tx.commit()`.
                }
                assert_eq!(state(&alice), before);
                assert_eq!(alice.kem_ratchet.as_ref().unwrap().pending_offer_count(), 0);
                let msg = alice.encrypt(b"pq-still-in-sync").unwrap();
                assert_eq!(bob.decrypt(&msg).unwrap(), b"pq-still-in-sync");
            }
        }

        #[test]
        #[cfg(any(feature = "prost", feature = "serde"))]
        fn pq_state_serialization_roundtrip_carries_on() {
            for suite in enabled_suites() {
                let (mut alice, mut bob) = pq_session(suite, KemRatchetConfig::every_turn());
                let a0_delayed = alice.encrypt(b"a0-delayed").unwrap();
                let a1 = alice.encrypt(b"a1").unwrap();
                assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
                let b0 = bob.encrypt(b"b0").unwrap();

                // Save and restore BOTH Alice (with pending offer!) and Bob (with active send ct +
                // skipped key + pending offer!) across all enabled formats.
                for (mut alice, mut bob) in restored(&alice).into_iter().zip(restored(&bob)) {
                    assert_eq!(alice.pq_suite(), Some(suite));
                    assert_eq!(bob.pq_suite(), Some(suite));
                    assert_eq!(bob.decrypt(&a0_delayed).unwrap(), b"a0-delayed");
                    assert_eq!(alice.decrypt(&b0).unwrap(), b"b0");

                    for round in 0..4 {
                        let a = alice.encrypt(format!("post-a-{round}").as_bytes()).unwrap();
                        assert_eq!(
                            bob.decrypt(&a).unwrap(),
                            format!("post-a-{round}").as_bytes()
                        );
                        let b = bob.encrypt(format!("post-b-{round}").as_bytes()).unwrap();
                        assert_eq!(
                            alice.decrypt(&b).unwrap(),
                            format!("post-b-{round}").as_bytes()
                        );
                    }
                }
            }
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_duplicate_skipped_message_numbers() {
        let (mut alice, mut bob) = session();
        let _m0 = alice.encrypt(b"m0").unwrap();
        let m1 = alice.encrypt(b"m1").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"m1");
        let json = serde_json::to_string(&bob).unwrap();
        // Inject a duplicate skipped message number `"0"` in `skipped_message_keys.chains[0].keys`.
        let needle = r#""keys":{"0":"#;
        let idx = json.find(needle).expect("expected skipped key 0 in JSON");
        let key_end = json[idx + needle.len()..]
            .find(']')
            .map(|rel| idx + needle.len() + rel + 1)
            .expect("expected end of key array");
        let entry = &json[idx + r#""keys":{"#.len()..key_end];
        let dup_json = format!("{},{entry}{}", &json[..key_end], &json[key_end..]);
        assert!(
            serde_json::from_str::<Party>(&dup_json).is_err(),
            "serde must reject duplicate skipped message numbers"
        );
    }
}
