//! The party who participates in the E2EE chat.

mod skipped;

use std::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit, KeySizeUser,
    aead::{Aead, AeadCore, Payload, array::typenum::Unsigned},
};
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, digest::OutputSizeUser};
use prost::Message as _;
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
use ratchetx2::pq::{KEM_KEY_ID_LENGTH, KemHeader, KemRatchet, KemRatchetConfig, PqSuite};
use ratchetx2::{
    Ratchet,
    error::CryptoError,
    key::{HeaderKey, KEY_LENGTH, MessageKey},
};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

/// The party who participates in the E2EE chat: encrypts and decrypts messages, without I/O.
/// See the example in the [crate docs](crate).
///
/// To keep a session between runs, it serializes with the `serde` or `rkyv` feature, and with
/// `prost` it converts to and from `proto::Party`, all with its keys: keep the output secret.
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "PartyUnchecked")
)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    rkyv(bytecheck(verify))
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
    #[cfg_attr(feature = "serde", serde(default))]
    current_chain_evicted: EvictedSet,
    /// Optional post-quantum KEM ratchet state; `None` in classical sessions.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    #[cfg_attr(feature = "serde", serde(default))]
    kem_ratchet: Option<KemRatchet>,
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
    /// New a party.
    ///
    /// # Args
    /// - associated_data: used in encryption
    pub fn new(ratchet: Ratchet, associated_data: impl AsRef<[u8]>) -> Self {
        Self {
            ratchet,
            skipped_message_keys: SkippedKeys::default(),
            previous_chain_length: 0,
            message_number_sender: 0,
            message_number_receiver: 0,
            associated_data: associated_data.as_ref().to_vec(),
            current_chain_evicted: EvictedSet::default(),
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            kem_ratchet: None,
        }
    }

    /// Create a party with post-quantum KEM ratcheting enabled using default cadence.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn new_pq(ratchet: Ratchet, associated_data: impl AsRef<[u8]>, suite: PqSuite) -> Self {
        Self::new_pq_with_config(ratchet, associated_data, suite, KemRatchetConfig::default())
    }

    /// Create a party with post-quantum KEM ratcheting enabled and custom rekey cadence.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn new_pq_with_config(
        ratchet: Ratchet,
        associated_data: impl AsRef<[u8]>,
        suite: PqSuite,
        config: KemRatchetConfig,
    ) -> Self {
        let mut party = Self::new(ratchet, associated_data);
        party.kem_ratchet = Some(KemRatchet::with_config(suite, config));
        party
    }

    /// Enable post-quantum KEM ratcheting on this party using default cadence.
    ///
    /// If the same `suite` is already enabled, this is a no-op so pending KEM offer seeds and
    /// active ciphertexts are preserved. Returns [`ErrorKind::Crypto`] if a different PQ suite
    /// is already enabled.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn enable_pq_ratchet(&mut self, suite: PqSuite) -> Result<()> {
        self.enable_pq_ratchet_with_config(suite, KemRatchetConfig::default())
    }

    /// Enable post-quantum KEM ratcheting on this party with custom rekey cadence.
    ///
    /// If the same `suite` is already enabled, this is a no-op so pending KEM offer seeds and
    /// active ciphertexts are preserved. Returns [`ErrorKind::Crypto`] if a different PQ suite
    /// is already enabled.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn enable_pq_ratchet_with_config(
        &mut self,
        suite: PqSuite,
        config: KemRatchetConfig,
    ) -> Result<()> {
        if let Some(existing) = &self.kem_ratchet {
            if existing.suite() == suite {
                return Ok(());
            }
            return Err(ErrorKind::Crypto.into());
        }
        self.kem_ratchet = Some(KemRatchet::with_config(suite, config));
        Ok(())
    }

    /// The configured post-quantum KEM suite, if PQ ratcheting is enabled.
    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
    pub fn pq_suite(&self) -> Option<PqSuite> {
        self.kem_ratchet.as_ref().map(KemRatchet::suite)
    }

    /// Associated data bound to every header and message in this session.
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }

    /// Whether post-quantum KEM ratcheting is active on this party.
    pub fn is_pq_ratchet_active(&self) -> bool {
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            self.kem_ratchet.is_some()
        }
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        {
            false
        }
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

        let mut ratchet = self.ratchet.clone();
        let header_key = Zeroizing::new(
            ratchet
                .header_key_sender()
                .ok_or(ErrorKind::NoSendingChain)?,
        );

        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let (kem_ratchet, pq_suite, pq_public_key, pq_ciphertext, pq_key_id) = {
            let mut kem = self.kem_ratchet.clone();
            let kem_header = match &mut kem {
                Some(k) => Some(k.prepare_send()?),
                None => None,
            };
            match kem_header {
                Some(kh) => (
                    kem,
                    kh.suite.map(u32::from),
                    kh.ek.map(Bytes::from),
                    kh.ct.map(Bytes::from),
                    kh.ek_id.map(|id| Bytes::copy_from_slice(&id)),
                ),
                None => (kem, None, None, None, None),
            }
        };
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        let (pq_suite, pq_public_key, pq_ciphertext, pq_key_id) = (None, None, None, None);

        let header = Header {
            public_key: Bytes::copy_from_slice(&ratchet.public_key()),
            previous_chain_length: self.previous_chain_length,
            message_number: self.message_number_sender,
            pq_suite,
            pq_public_key,
            pq_ciphertext,
            pq_key_id,
        };
        let header_bytes = Zeroizing::new(header.encode_to_vec());
        let header = encrypt(
            &header_key,
            HEADER_INFO,
            &self.associated_data,
            &header_bytes,
        )?;
        let message_key = Zeroizing::new(
            ratchet
                .step_message_ratchet_sender()
                .ok_or(ErrorKind::NoSendingChain)?,
        );
        let content = encrypt(
            &message_key,
            CONTENT_INFO,
            &content_associated_data(&self.associated_data, &header),
            content,
        )?;

        // Commit state only after both fallible encryptions succeed.
        self.ratchet = ratchet;
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            self.kem_ratchet = kem_ratchet;
        }
        self.message_number_sender = next_message_number;
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
        if let Some(header_key) = self.ratchet.header_key_receiver() {
            let header_key = Zeroizing::new(header_key);
            if let Some(header) = self.open_header(&header_key, message) {
                return self.receive_current_chain(&header?, message);
            }
        }
        let next_header_key = Zeroizing::new(self.ratchet.next_header_key_receiver());
        if let Some(header) = self.open_header(&next_header_key, message) {
            return self.receive_next_chain(&header?, message);
        }
        Err(ErrorKind::Undecryptable.into())
    }

    /// A message whose key was skipped earlier, because it arrived out of order.
    fn receive_skipped(&mut self, message: &EncryptedMessage) -> Result<Option<Vec<u8>>> {
        let Some((header_key, header)) = self
            .skipped_message_keys
            .header_keys()
            .find_map(|header_key| {
                let header_key = Zeroizing::new(header_key);
                let header = self.open_header(&header_key, message)?;
                Some((header_key, header))
            })
        else {
            return Ok(None);
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
            return Ok(None);
        };
        let content = self.open_content(&message_key, message)?;
        self.skipped_message_keys
            .remove(&header_key, header.message_number);
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        if let Some(kem) = &mut self.kem_ratchet {
            kem.note_skipped_received();
        }
        Ok(Some(content))
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

        let mut ratchet = self.ratchet.clone();
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let mut kem_ratchet = self.kem_ratchet.clone();
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        match &mut kem_ratchet {
            Some(kem) => {
                let kem_header = kem_header_from_proto(header)?;
                kem.receive_current_chain(&kem_header)
                    .map_err(|e| Error::new(ErrorKind::InvalidHeader, e))?;
            }
            None => ensure_no_pq_header(header)?,
        }
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        ensure_no_pq_header(header)?;

        let skipped = skip_message_keys(
            &mut ratchet,
            self.message_number_receiver,
            header.message_number,
        )?;
        let message_key = Zeroizing::new(
            ratchet
                .step_message_ratchet_receiver()
                .ok_or(ErrorKind::InvalidHeader)?,
        );
        let content = self.open_content(&message_key, message)?;

        let current_recv_hk = ratchet.header_key_receiver().map(Zeroizing::new);
        self.ratchet = ratchet;
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            self.kem_ratchet = kem_ratchet;
        }
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

        let mut ratchet = self.ratchet.clone();
        let prev_recv_hk = ratchet.header_key_receiver().map(Zeroizing::new);
        let skipped_previous = skip_message_keys(
            &mut ratchet,
            self.message_number_receiver,
            header.previous_chain_length,
        )?;

        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let mut kem_ratchet = self.kem_ratchet.clone();
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let (kem_recv_ss, kem_send_ss) = match &mut kem_ratchet {
            Some(kem) => {
                let kem_header = kem_header_from_proto(header)?;
                kem.receive_chain_step(&kem_header)
                    .map_err(|e| Error::new(ErrorKind::InvalidHeader, e))?
            }
            None => {
                ensure_no_pq_header(header)?;
                (None, None)
            }
        };
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        ensure_no_pq_header(header)?;

        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            let recv_extra: &[u8] = kem_recv_ss.as_deref().map_or(&[], |s| s.as_slice());
            ratchet
                .step_dh_root_with(&header.public_key, recv_extra)
                .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;
            let send_extra: &[u8] = kem_send_ss.as_deref().map_or(&[], |s| s.as_slice());
            ratchet
                .step_dh_root_with(&header.public_key, send_extra)
                .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;
        }
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        {
            for _ in 0..2 {
                ratchet
                    .step_dh_root(&header.public_key)
                    .map_err(|e| Error::new(ErrorKind::InvalidPublicKey, e))?;
            }
        }

        let skipped_next = skip_message_keys(&mut ratchet, 0, header.message_number)?;
        let message_key = Zeroizing::new(
            ratchet
                .step_message_ratchet_receiver()
                .ok_or(ErrorKind::InvalidHeader)?,
        );
        let content = self.open_content(&message_key, message)?;

        // Commit BOTH ratchets only after content AEAD succeeds.
        let new_recv_hk = ratchet.header_key_receiver().map(Zeroizing::new);
        self.ratchet = ratchet;
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        {
            self.kem_ratchet = kem_ratchet;
        }
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

    /// Decrypt the content with `message_key`; it only authenticates with the encrypted header
    /// it was sent with.
    fn open_content(&self, message_key: &MessageKey, message: &EncryptedMessage) -> Result<Vec<u8>> {
        decrypt(
            message_key,
            CONTENT_INFO,
            &content_associated_data(&self.associated_data, &message.header),
            &message.content,
        )
        .map_err(|e| Error::new(ErrorKind::Undecryptable, e))
    }

    /// Validate all party invariants on deserialization.
    #[cfg(any(feature = "serde", feature = "prost"))]
    fn validate(&self) -> Result<()> {
        self.skipped_message_keys.validate()?;
        self.current_chain_evicted
            .validate(Some(self.message_number_receiver))?;
        if self.ratchet.header_key_sender().is_none()
            && (self.message_number_sender != 0 || self.previous_chain_length != 0)
        {
            return Err(ErrorKind::MalformedState.into());
        }
        match self.ratchet.header_key_receiver() {
            None => {
                if self.message_number_receiver != 0
                    || !self.skipped_message_keys.is_empty()
                    || !self.current_chain_evicted.is_empty()
                {
                    return Err(ErrorKind::MalformedState.into());
                }
            }
            Some(recv_hk) => {
                let recv_hk = Zeroizing::new(recv_hk);
                self.skipped_message_keys
                    .validate_for_current_receiver(&recv_hk, self.message_number_receiver)?;
            }
        }
        Ok(())
    }
}

/// Reject any PQ header fields when PQ ratcheting is disabled.
fn ensure_no_pq_header(header: &Header) -> Result<()> {
    if header.pq_suite.is_some()
        || header.pq_public_key.is_some()
        || header.pq_ciphertext.is_some()
        || header.pq_key_id.is_some()
    {
        return Err(ErrorKind::InvalidHeader.into());
    }
    Ok(())
}

/// Convert wire protobuf PQ header fields to [`KemHeader`].
#[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
fn kem_header_from_proto(header: &Header) -> Result<KemHeader> {
    let suite = match header.pq_suite {
        Some(v) => Some(u8::try_from(v).map_err(|_| ErrorKind::InvalidHeader)?),
        None => None,
    };
    let ek_id = match &header.pq_key_id {
        Some(bytes) => Some(
            <[u8; KEM_KEY_ID_LENGTH]>::try_from(bytes.as_ref())
                .map_err(|_| ErrorKind::InvalidHeader)?,
        ),
        None => None,
    };
    Ok(KemHeader {
        suite,
        ek: header.pq_public_key.as_ref().map(|b| b.to_vec()),
        ct: header.pq_ciphertext.as_ref().map(|b| b.to_vec()),
        ek_id,
    })
}

#[cfg(all(
    feature = "serde",
    any(feature = "ml-kem-1024", feature = "ml-kem-768")
))]
#[derive(serde::Deserialize)]
#[serde(rename = "Party")]
struct PartyUnchecked {
    ratchet: Ratchet,
    skipped_message_keys: SkippedKeys,
    previous_chain_length: u64,
    message_number_sender: u64,
    message_number_receiver: u64,
    associated_data: Vec<u8>,
    #[serde(default)]
    current_chain_evicted: EvictedSet,
    #[serde(default)]
    kem_ratchet: Option<KemRatchet>,
}

#[cfg(all(
    feature = "serde",
    not(any(feature = "ml-kem-1024", feature = "ml-kem-768"))
))]
struct PartyUnchecked {
    ratchet: Ratchet,
    skipped_message_keys: SkippedKeys,
    previous_chain_length: u64,
    message_number_sender: u64,
    message_number_receiver: u64,
    associated_data: Vec<u8>,
    current_chain_evicted: EvictedSet,
    kem_ratchet: Option<serde::de::IgnoredAny>,
}

#[cfg(all(
    feature = "serde",
    not(any(feature = "ml-kem-1024", feature = "ml-kem-768"))
))]
impl<'de> serde::Deserialize<'de> for PartyUnchecked {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "ratchet",
            "skipped_message_keys",
            "previous_chain_length",
            "message_number_sender",
            "message_number_receiver",
            "associated_data",
            "current_chain_evicted",
        ];

        enum Field {
            Ratchet,
            SkippedMessageKeys,
            PreviousChainLength,
            MessageNumberSender,
            MessageNumberReceiver,
            AssociatedData,
            CurrentChainEvicted,
            KemRatchet,
            Ignore,
        }

        impl<'de> serde::Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct FieldVisitor;

                impl serde::de::Visitor<'_> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("field identifier")
                    }

                    fn visit_u64<E>(self, v: u64) -> core::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok(match v {
                            0 => Field::Ratchet,
                            1 => Field::SkippedMessageKeys,
                            2 => Field::PreviousChainLength,
                            3 => Field::MessageNumberSender,
                            4 => Field::MessageNumberReceiver,
                            5 => Field::AssociatedData,
                            6 => Field::CurrentChainEvicted,
                            7 => Field::KemRatchet,
                            _ => Field::Ignore,
                        })
                    }

                    fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok(match v {
                            "ratchet" => Field::Ratchet,
                            "skipped_message_keys" => Field::SkippedMessageKeys,
                            "previous_chain_length" => Field::PreviousChainLength,
                            "message_number_sender" => Field::MessageNumberSender,
                            "message_number_receiver" => Field::MessageNumberReceiver,
                            "associated_data" => Field::AssociatedData,
                            "current_chain_evicted" => Field::CurrentChainEvicted,
                            "kem_ratchet" => Field::KemRatchet,
                            _ => Field::Ignore,
                        })
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok(match v {
                            b"ratchet" => Field::Ratchet,
                            b"skipped_message_keys" => Field::SkippedMessageKeys,
                            b"previous_chain_length" => Field::PreviousChainLength,
                            b"message_number_sender" => Field::MessageNumberSender,
                            b"message_number_receiver" => Field::MessageNumberReceiver,
                            b"associated_data" => Field::AssociatedData,
                            b"current_chain_evicted" => Field::CurrentChainEvicted,
                            b"kem_ratchet" => Field::KemRatchet,
                            _ => Field::Ignore,
                        })
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct PartyVisitor;

        impl<'de> serde::de::Visitor<'de> for PartyVisitor {
            type Value = PartyUnchecked;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("struct Party")
            }

            fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let ratchet = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(0, &"struct Party with 7 elements")
                })?;
                let skipped_message_keys = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(1, &"struct Party with 7 elements")
                })?;
                let previous_chain_length = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(2, &"struct Party with 7 elements")
                })?;
                let message_number_sender = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(3, &"struct Party with 7 elements")
                })?;
                let message_number_receiver = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(4, &"struct Party with 7 elements")
                })?;
                let associated_data = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(5, &"struct Party with 7 elements")
                })?;
                let current_chain_evicted = seq.next_element()?.unwrap_or_default();
                Ok(PartyUnchecked {
                    ratchet,
                    skipped_message_keys,
                    previous_chain_length,
                    message_number_sender,
                    message_number_receiver,
                    associated_data,
                    current_chain_evicted,
                    kem_ratchet: None,
                })
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut ratchet = None;
                let mut skipped_message_keys = None;
                let mut previous_chain_length = None;
                let mut message_number_sender = None;
                let mut message_number_receiver = None;
                let mut associated_data = None;
                let mut current_chain_evicted = None;
                let mut kem_ratchet: Option<Option<serde::de::IgnoredAny>> = None;

                while let Some(key) = map.next_key::<Field>()? {
                    match key {
                        Field::Ratchet => {
                            if ratchet.is_some() {
                                return Err(serde::de::Error::duplicate_field("ratchet"));
                            }
                            ratchet = Some(map.next_value()?);
                        }
                        Field::SkippedMessageKeys => {
                            if skipped_message_keys.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "skipped_message_keys",
                                ));
                            }
                            skipped_message_keys = Some(map.next_value()?);
                        }
                        Field::PreviousChainLength => {
                            if previous_chain_length.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "previous_chain_length",
                                ));
                            }
                            previous_chain_length = Some(map.next_value()?);
                        }
                        Field::MessageNumberSender => {
                            if message_number_sender.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "message_number_sender",
                                ));
                            }
                            message_number_sender = Some(map.next_value()?);
                        }
                        Field::MessageNumberReceiver => {
                            if message_number_receiver.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "message_number_receiver",
                                ));
                            }
                            message_number_receiver = Some(map.next_value()?);
                        }
                        Field::AssociatedData => {
                            if associated_data.is_some() {
                                return Err(serde::de::Error::duplicate_field("associated_data"));
                            }
                            associated_data = Some(map.next_value()?);
                        }
                        Field::CurrentChainEvicted => {
                            if current_chain_evicted.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "current_chain_evicted",
                                ));
                            }
                            current_chain_evicted = Some(map.next_value()?);
                        }
                        Field::KemRatchet => {
                            if kem_ratchet.is_some() {
                                return Err(serde::de::Error::duplicate_field("kem_ratchet"));
                            }
                            kem_ratchet = Some(map.next_value()?);
                        }
                        Field::Ignore => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                Ok(PartyUnchecked {
                    ratchet: ratchet.ok_or_else(|| serde::de::Error::missing_field("ratchet"))?,
                    skipped_message_keys: skipped_message_keys
                        .ok_or_else(|| serde::de::Error::missing_field("skipped_message_keys"))?,
                    previous_chain_length: previous_chain_length
                        .ok_or_else(|| serde::de::Error::missing_field("previous_chain_length"))?,
                    message_number_sender: message_number_sender
                        .ok_or_else(|| serde::de::Error::missing_field("message_number_sender"))?,
                    message_number_receiver: message_number_receiver.ok_or_else(|| {
                        serde::de::Error::missing_field("message_number_receiver")
                    })?,
                    associated_data: associated_data
                        .ok_or_else(|| serde::de::Error::missing_field("associated_data"))?,
                    current_chain_evicted: current_chain_evicted.unwrap_or_default(),
                    kem_ratchet: kem_ratchet.flatten(),
                })
            }
        }

        deserializer.deserialize_struct("Party", FIELDS, PartyVisitor)
    }
}

#[cfg(feature = "serde")]
impl TryFrom<PartyUnchecked> for Party {
    type Error = Error;

    fn try_from(raw: PartyUnchecked) -> Result<Self> {
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        if raw.kem_ratchet.is_some() {
            // Fail closed: never silently drop PQ ratchet state on a non-PQ build.
            return Err(ErrorKind::MalformedState.into());
        }
        let party = Self {
            ratchet: raw.ratchet,
            skipped_message_keys: raw.skipped_message_keys,
            previous_chain_length: raw.previous_chain_length,
            message_number_sender: raw.message_number_sender,
            message_number_receiver: raw.message_number_receiver,
            associated_data: raw.associated_data,
            current_chain_evicted: raw.current_chain_evicted,
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            kem_ratchet: raw.kem_ratchet,
        };
        party.validate()?;
        Ok(party)
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedParty {
    /// Associated data bound to every header and message in this archived session.
    pub fn associated_data(&self) -> &[u8] {
        self.associated_data.as_slice()
    }
}

#[cfg(feature = "rkyv")]
unsafe impl<C> rkyv::bytecheck::Verify<C> for ArchivedParty
where
    C: rkyv::rancor::Fallible + ?Sized,
    C::Error: rkyv::rancor::Source,
{
    fn verify(&self, _context: &mut C) -> core::result::Result<(), C::Error> {
        use rkyv::rancor::Source;
        let check = || -> Result<()> {
            let msg_recv = self.message_number_receiver.to_native();
            let msg_send = self.message_number_sender.to_native();
            let prev_len = self.previous_chain_length.to_native();
            self.current_chain_evicted
                .validate_with_bound(Some(msg_recv))?;
            if self.ratchet.header_key_sender().is_none() && (msg_send != 0 || prev_len != 0) {
                return Err(ErrorKind::MalformedState.into());
            }
            match self.ratchet.header_key_receiver() {
                None => {
                    if msg_recv != 0
                        || !self.skipped_message_keys.is_empty()
                        || !self.current_chain_evicted.is_empty()
                    {
                        return Err(ErrorKind::MalformedState.into());
                    }
                }
                Some(recv_hk) => {
                    let recv_hk = Zeroizing::new(recv_hk);
                    self.skipped_message_keys
                        .validate_for_current_receiver(&recv_hk, msg_recv)?;
                }
            }
            Ok(())
        };
        check().map_err(C::Error::new)
    }
}

#[cfg(feature = "prost")]
impl From<&Party> for crate::proto::Party {
    fn from(party: &Party) -> Self {
        let (current_chain_evicted, current_chain_evicted_below) =
            party.current_chain_evicted.to_proto();
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let kem_ratchet = party.kem_ratchet.as_ref().map(Into::into);
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        let kem_ratchet = None;
        Self {
            ratchet: Some((&party.ratchet).into()),
            skipped_chains: party.skipped_message_keys.to_proto(),
            previous_chain_length: party.previous_chain_length,
            message_number_sender: party.message_number_sender,
            message_number_receiver: party.message_number_receiver,
            associated_data: party.associated_data.clone(),
            current_chain_evicted,
            current_chain_evicted_below,
            kem_ratchet,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&crate::proto::Party> for Party {
    type Error = Error;

    fn try_from(party: &crate::proto::Party) -> Result<Self> {
        let ratchet = party.ratchet.as_ref().ok_or(ErrorKind::MalformedState)?;
        #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
        if party.kem_ratchet.is_some() {
            // Fail closed: never silently drop PQ ratchet state on a non-PQ build.
            return Err(ErrorKind::MalformedState.into());
        }
        #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
        let kem_ratchet = match &party.kem_ratchet {
            Some(kem) => Some(
                KemRatchet::try_from(kem).map_err(|e| Error::new(ErrorKind::MalformedState, e))?,
            ),
            None => None,
        };
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
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
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
    let header_key = Zeroizing::new(
        ratchet
            .header_key_receiver()
            .ok_or(ErrorKind::InvalidHeader)?,
    );
    let mut skipped = SkippedChain::new(*header_key);
    for message_number in from..until {
        let message_key = Zeroizing::new(
            ratchet
                .step_message_ratchet_receiver()
                .ok_or(ErrorKind::InvalidHeader)?,
        );
        skipped.insert(message_number, *message_key);
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
    Hkdf::<Sha256>::new(Some(&[0; HASH_LEN]), key)
        .expand_multi_info(&[info, nonce], keys.as_mut_slice())
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
            #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
            party.kem_ratchet.as_ref().map(KemRatchet::pending_offer_count),
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
        let mut header = receiver.open_header(&header_key, message).unwrap().unwrap();
        alter(&mut header);
        let header = encrypt(&header_key, HEADER_INFO, b"AD", &header.encode_to_vec()).unwrap();
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
        let forged = reencrypt_header(&bob, hk, &msg, |h| {
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
    #[cfg(any(feature = "prost", feature = "serde", feature = "rkyv"))]
    fn restored(party: &Party) -> Vec<Party> {
        Vec::from([
            #[cfg(feature = "prost")]
            Party::try_from(&crate::proto::Party::from(party)).unwrap(),
            #[cfg(feature = "serde")]
            serde_json::from_str(&serde_json::to_string(party).unwrap()).unwrap(),
            #[cfg(feature = "rkyv")]
            rkyv::from_bytes::<_, rkyv::rancor::Error>(
                &rkyv::to_bytes::<rkyv::rancor::Error>(party).unwrap(),
            )
            .unwrap(),
        ])
    }

    #[test]
    #[cfg(any(feature = "prost", feature = "serde", feature = "rkyv"))]
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
    #[cfg(any(feature = "prost", feature = "serde", feature = "rkyv"))]
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

            #[cfg(not(any(feature = "ml-kem-1024", feature = "ml-kem-768")))]
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

        #[cfg(all(
            feature = "prost",
            not(any(feature = "ml-kem-1024", feature = "ml-kem-768"))
        ))]
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

        #[cfg(feature = "rkyv")]
        {
            let mut bad = bob;
            bad.message_number_sender = 3;
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&bad).unwrap();
            assert!(rkyv::from_bytes::<Party, rkyv::rancor::Error>(&bytes).is_err());
        }
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

        #[cfg(feature = "rkyv")]
        {
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&custom_bob).unwrap();
            let archived = rkyv::access::<ArchivedParty, rkyv::rancor::Error>(&bytes).unwrap();
            assert_eq!(archived.associated_data(), &custom_ad);
        }
    }

    #[test]
    #[cfg(all(
        feature = "serde",
        not(any(feature = "ml-kem-1024", feature = "ml-kem-768"))
    ))]
    fn non_pq_positional_serde_roundtrip_and_json_kem_ratchet_fail_closed() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug)]
        struct PosError(String);

        impl fmt::Display for PosError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::error::Error for PosError {}

        impl serde::ser::Error for PosError {
            fn custom<T: fmt::Display>(msg: T) -> Self {
                Self(msg.to_string())
            }
        }

        impl serde::de::Error for PosError {
            fn custom<T: fmt::Display>(msg: T) -> Self {
                Self(msg.to_string())
            }
        }

        struct PosSer {
            out: Vec<u8>,
            struct_names: Vec<&'static str>,
        }

        impl PosSer {
            fn new() -> Self {
                Self {
                    out: Vec::new(),
                    struct_names: Vec::new(),
                }
            }
        }

        impl serde::Serializer for &mut PosSer {
            type Ok = ();
            type Error = PosError;
            type SerializeSeq = Self;
            type SerializeTuple = Self;
            type SerializeTupleStruct = serde::ser::Impossible<(), PosError>;
            type SerializeTupleVariant = serde::ser::Impossible<(), PosError>;
            type SerializeMap = Self;
            type SerializeStruct = Self;
            type SerializeStructVariant = serde::ser::Impossible<(), PosError>;

            fn serialize_bool(self, v: bool) -> core::result::Result<(), PosError> {
                self.out.push(u8::from(v));
                Ok(())
            }
            fn serialize_i8(self, _: i8) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_i16(self, _: i16) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_i32(self, _: i32) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_i64(self, _: i64) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_u8(self, v: u8) -> core::result::Result<(), PosError> {
                self.out.push(v);
                Ok(())
            }
            fn serialize_u16(self, _: u16) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_u32(self, v: u32) -> core::result::Result<(), PosError> {
                self.out.extend_from_slice(&v.to_le_bytes());
                Ok(())
            }
            fn serialize_u64(self, v: u64) -> core::result::Result<(), PosError> {
                self.out.extend_from_slice(&v.to_le_bytes());
                Ok(())
            }
            fn serialize_f32(self, _: f32) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_f64(self, _: f64) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_char(self, _: char) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_str(self, _: &str) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_bytes(self, _: &[u8]) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_none(self) -> core::result::Result<(), PosError> {
                self.out.push(0);
                Ok(())
            }
            fn serialize_some<T: ?Sized + Serialize>(
                self,
                value: &T,
            ) -> core::result::Result<(), PosError> {
                self.out.push(1);
                value.serialize(self)
            }
            fn serialize_unit(self) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_unit_struct(self, _: &'static str) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_unit_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
            ) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_newtype_struct<T: ?Sized + Serialize>(
                self,
                _: &'static str,
                value: &T,
            ) -> core::result::Result<(), PosError> {
                value.serialize(self)
            }
            fn serialize_newtype_variant<T: ?Sized + Serialize>(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: &T,
            ) -> core::result::Result<(), PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_seq(
                self,
                len: Option<usize>,
            ) -> core::result::Result<Self::SerializeSeq, PosError> {
                let len = len.ok_or_else(|| PosError("seq len required".into()))?;
                self.out.extend_from_slice(&(len as u64).to_le_bytes());
                Ok(self)
            }
            fn serialize_tuple(
                self,
                _: usize,
            ) -> core::result::Result<Self::SerializeTuple, PosError> {
                Ok(self)
            }
            fn serialize_tuple_struct(
                self,
                _: &'static str,
                _: usize,
            ) -> core::result::Result<Self::SerializeTupleStruct, PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_tuple_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: usize,
            ) -> core::result::Result<Self::SerializeTupleVariant, PosError> {
                Err(PosError("unsupported".into()))
            }
            fn serialize_map(
                self,
                len: Option<usize>,
            ) -> core::result::Result<Self::SerializeMap, PosError> {
                let len = len.ok_or_else(|| PosError("map len required".into()))?;
                self.out.extend_from_slice(&(len as u64).to_le_bytes());
                Ok(self)
            }
            fn serialize_struct(
                self,
                name: &'static str,
                _: usize,
            ) -> core::result::Result<Self::SerializeStruct, PosError> {
                self.struct_names.push(name);
                Ok(self)
            }
            fn serialize_struct_variant(
                self,
                _: &'static str,
                _: u32,
                _: &'static str,
                _: usize,
            ) -> core::result::Result<Self::SerializeStructVariant, PosError> {
                Err(PosError("unsupported".into()))
            }
        }

        impl serde::ser::SerializeSeq for &mut PosSer {
            type Ok = ();
            type Error = PosError;
            fn serialize_element<T: ?Sized + Serialize>(
                &mut self,
                value: &T,
            ) -> core::result::Result<(), PosError> {
                value.serialize(&mut **self)
            }
            fn end(self) -> core::result::Result<(), PosError> {
                Ok(())
            }
        }

        impl serde::ser::SerializeTuple for &mut PosSer {
            type Ok = ();
            type Error = PosError;
            fn serialize_element<T: ?Sized + Serialize>(
                &mut self,
                value: &T,
            ) -> core::result::Result<(), PosError> {
                value.serialize(&mut **self)
            }
            fn end(self) -> core::result::Result<(), PosError> {
                Ok(())
            }
        }

        impl serde::ser::SerializeMap for &mut PosSer {
            type Ok = ();
            type Error = PosError;
            fn serialize_key<T: ?Sized + Serialize>(
                &mut self,
                key: &T,
            ) -> core::result::Result<(), PosError> {
                key.serialize(&mut **self)
            }
            fn serialize_value<T: ?Sized + Serialize>(
                &mut self,
                value: &T,
            ) -> core::result::Result<(), PosError> {
                value.serialize(&mut **self)
            }
            fn end(self) -> core::result::Result<(), PosError> {
                Ok(())
            }
        }

        impl serde::ser::SerializeStruct for &mut PosSer {
            type Ok = ();
            type Error = PosError;
            fn serialize_field<T: ?Sized + Serialize>(
                &mut self,
                _: &'static str,
                value: &T,
            ) -> core::result::Result<(), PosError> {
                value.serialize(&mut **self)
            }
            fn end(self) -> core::result::Result<(), PosError> {
                Ok(())
            }
        }

        struct PosDe<'de> {
            input: &'de [u8],
            struct_names: Vec<&'static str>,
        }

        impl<'de> PosDe<'de> {
            fn new(input: &'de [u8]) -> Self {
                Self {
                    input,
                    struct_names: Vec::new(),
                }
            }

            fn take(&mut self, n: usize) -> core::result::Result<&'de [u8], PosError> {
                if self.input.len() < n {
                    return Err(PosError("unexpected eof".into()));
                }
                let (head, tail) = self.input.split_at(n);
                self.input = tail;
                Ok(head)
            }

            fn read_u8(&mut self) -> core::result::Result<u8, PosError> {
                Ok(self.take(1)?[0])
            }

            fn read_u32(&mut self) -> core::result::Result<u32, PosError> {
                Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
            }

            fn read_u64(&mut self) -> core::result::Result<u64, PosError> {
                Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
            }
        }

        struct FixedSeq<'a, 'de> {
            de: &'a mut PosDe<'de>,
            remaining: usize,
        }

        impl<'de> serde::de::SeqAccess<'de> for FixedSeq<'_, 'de> {
            type Error = PosError;

            fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
                &mut self,
                seed: T,
            ) -> core::result::Result<Option<T::Value>, PosError> {
                if self.remaining == 0 {
                    return Ok(None);
                }
                self.remaining -= 1;
                seed.deserialize(&mut *self.de).map(Some)
            }
        }

        struct FixedMap<'a, 'de> {
            de: &'a mut PosDe<'de>,
            remaining: usize,
        }

        impl<'de> serde::de::MapAccess<'de> for FixedMap<'_, 'de> {
            type Error = PosError;

            fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
                &mut self,
                seed: K,
            ) -> core::result::Result<Option<K::Value>, PosError> {
                if self.remaining == 0 {
                    return Ok(None);
                }
                self.remaining -= 1;
                seed.deserialize(&mut *self.de).map(Some)
            }

            fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(
                &mut self,
                seed: V,
            ) -> core::result::Result<V::Value, PosError> {
                seed.deserialize(&mut *self.de)
            }
        }

        impl<'de> serde::Deserializer<'de> for &mut PosDe<'de> {
            type Error = PosError;

            fn deserialize_any<V: serde::de::Visitor<'de>>(
                self,
                _: V,
            ) -> core::result::Result<V::Value, PosError> {
                Err(PosError("non-self-describing positional format".into()))
            }

            fn deserialize_bool<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                match self.read_u8()? {
                    0 => visitor.visit_bool(false),
                    1 => visitor.visit_bool(true),
                    v => Err(PosError(format!("invalid bool tag {v}"))),
                }
            }

            fn deserialize_u8<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                visitor.visit_u8(self.read_u8()?)
            }

            fn deserialize_u32<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                visitor.visit_u32(self.read_u32()?)
            }

            fn deserialize_u64<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                visitor.visit_u64(self.read_u64()?)
            }

            fn deserialize_option<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                match self.read_u8()? {
                    0 => visitor.visit_none(),
                    1 => visitor.visit_some(self),
                    v => Err(PosError(format!("invalid option tag {v}"))),
                }
            }

            fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
                self,
                _: &'static str,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                visitor.visit_newtype_struct(self)
            }

            fn deserialize_seq<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                let len = usize::try_from(self.read_u64()?)
                    .map_err(|_| PosError("seq len overflow".into()))?;
                visitor.visit_seq(FixedSeq {
                    de: self,
                    remaining: len,
                })
            }

            fn deserialize_tuple<V: serde::de::Visitor<'de>>(
                self,
                len: usize,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                visitor.visit_seq(FixedSeq {
                    de: self,
                    remaining: len,
                })
            }

            fn deserialize_struct<V: serde::de::Visitor<'de>>(
                self,
                name: &'static str,
                fields: &'static [&'static str],
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                self.struct_names.push(name);
                // Matches bincode/postcard: positional structs deserialize `fields.len()` elements.
                self.deserialize_tuple(fields.len(), visitor)
            }

            fn deserialize_map<V: serde::de::Visitor<'de>>(
                self,
                visitor: V,
            ) -> core::result::Result<V::Value, PosError> {
                let len = usize::try_from(self.read_u64()?)
                    .map_err(|_| PosError("map len overflow".into()))?;
                visitor.visit_map(FixedMap {
                    de: self,
                    remaining: len,
                })
            }

            serde::forward_to_deserialize_any! {
                i8 i16 i32 i64 i128 u16 u128 f32 f64 char str string bytes byte_buf
                unit unit_struct tuple_struct enum identifier ignored_any
            }
        }

        fn roundtrip<S: Serialize, D: for<'de> Deserialize<'de>>(value: &S) -> D {
            let mut ser = PosSer::new();
            value.serialize(&mut ser).unwrap();
            let mut de = PosDe::new(&ser.out);
            let out = D::deserialize(&mut de).unwrap();
            assert!(
                de.input.is_empty(),
                "trailing unconsumed bytes: {}",
                de.input.len()
            );
            assert_eq!(ser.struct_names, de.struct_names);
            out
        }

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
        let mut bob_restored: Party = roundtrip(&bob);
        assert_eq!(state(&bob_restored), before);
        assert_eq!(bob_restored.decrypt(&delayed).unwrap(), b"delayed");
        assert_eq!(
            bob_restored.decrypt(&evicted_msg).unwrap_err().kind(),
            ErrorKind::EvictedMessage
        );
        let follow_up = alice.encrypt(b"follow-up").unwrap();
        assert_eq!(bob_restored.decrypt(&follow_up).unwrap(), b"follow-up");

        // Nested positional roundtrip `(Party, u8)` mimicking `SessionState::Active { party, id, .. }`
        // across tags 0 (Option::None), 1 (Option::Some), 2 and 0xFF (invalid Option discriminants).
        for trailing_tag in [0u8, 1u8, 2u8, 0xFFu8] {
            let (restored_party, restored_tag): (Party, u8) = roundtrip(&(&bob, trailing_tag));
            assert_eq!(restored_tag, trailing_tag);
            assert_eq!(state(&restored_party), before);
        }

        // JSON map path: fail closed on any non-null `kem_ratchet`, accept `null` or omitted,
        // accept omitted `current_chain_evicted`, ignore unknown fields, reject duplicate key.
        let base_json = serde_json::to_string(&bob).unwrap();
        for bad_val in [
            serde_json::json!({"suite": "MlKem1024"}),
            serde_json::json!(1),
            serde_json::json!(false),
        ] {
            let mut val: serde_json::Value = serde_json::from_str(&base_json).unwrap();
            val["kem_ratchet"] = bad_val;
            let err = serde_json::from_value::<Party>(val).unwrap_err();
            assert!(
                err.to_string().contains("malformed"),
                "expected MalformedState error, got: {err}"
            );
        }

        let mut with_null: serde_json::Value = serde_json::from_str(&base_json).unwrap();
        with_null["kem_ratchet"] = serde_json::Value::Null;
        with_null["unknown_future_field"] = serde_json::json!({"ignored": true});
        assert_eq!(state(&serde_json::from_value::<Party>(with_null).unwrap()), before);

        // Legacy JSON without `current_chain_evicted` defaults cleanly.
        let (_a2, fresh_bob) = session();
        let mut legacy: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&fresh_bob).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("current_chain_evicted");
        assert!(serde_json::from_value::<Party>(legacy).is_ok());

        // Duplicate `kem_ratchet` key in raw JSON is rejected.
        let dup_json = format!(
            "{},\"kem_ratchet\":null,\"kem_ratchet\":null}}",
            base_json.trim_end_matches('}')
        );
        assert!(serde_json::from_str::<Party>(&dup_json).is_err());
    }

    #[cfg(any(feature = "ml-kem-1024", feature = "ml-kem-768"))]
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
                        let a_msg = alice
                            .encrypt(format!("alice-{round}").as_bytes())
                            .unwrap();
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
                    assert_eq!(alice.decrypt(&b).unwrap(), format!("epoch-b-{i}").as_bytes());
                }

                // Delayed messages from earlier KEM epochs STILL decrypt cleanly!
                assert_eq!(bob.decrypt(&a1_delayed).unwrap(), b"a1-delayed");
                assert_eq!(alice.decrypt(&b1_delayed).unwrap(), b"b1-delayed");
                // Replaying an earlier-epoch consumed message is rejected cleanly.
                assert_eq!(
                    bob.decrypt(&a1_delayed).unwrap_err().kind(),
                    ErrorKind::Undecryptable
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
        #[cfg(any(feature = "prost", feature = "serde", feature = "rkyv"))]
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
                        assert_eq!(bob.decrypt(&a).unwrap(), format!("post-a-{round}").as_bytes());
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
}
