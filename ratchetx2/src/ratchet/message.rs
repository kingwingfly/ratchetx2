use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::key::{ChainKey, HeaderKey, KEY_LENGTH, MessageKey};

/// An established chain: its ChainKey and the HeaderKey of its messages.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
struct Chain {
    chain_key: ChainKey,
    header_key: HeaderKey,
}

impl fmt::Debug for Chain {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain").finish_non_exhaustive()
    }
}

impl PartialEq for Chain {
    fn eq(&self, other: &Self) -> bool {
        bool::from(
            self.chain_key.ct_eq(&other.chain_key) & self.header_key.ct_eq(&other.header_key),
        )
    }
}

impl Eq for Chain {}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct MessageRatchet {
    /// None until a DH-root step sets up this chain.
    chain: Option<Chain>,
    pub next_header_key: HeaderKey,
}

impl fmt::Debug for MessageRatchet {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageRatchet")
            .field("has_chain", &self.chain.is_some())
            .finish_non_exhaustive()
    }
}

impl PartialEq for MessageRatchet {
    fn eq(&self, other: &Self) -> bool {
        let chain_eq = match (&self.chain, &other.chain) {
            (Some(a), Some(b)) => Choice::from(u8::from(a == b)),
            (None, None) => Choice::from(1),
            _ => Choice::from(0),
        };
        bool::from(chain_eq & self.next_header_key.ct_eq(&other.next_header_key))
    }
}

impl Eq for MessageRatchet {}

impl MessageRatchet {
    /// New a MessageRatchet.
    pub fn from_key(
        chain_key: Zeroizing<ChainKey>,
        header_key: HeaderKey,
        next_header_key: Zeroizing<HeaderKey>,
    ) -> Self {
        Self {
            chain: Some(Chain {
                chain_key: *chain_key,
                header_key,
            }),
            next_header_key: *next_header_key,
        }
    }

    /// New a MessageRatchet without a chain yet, supposed to be only used in initialization.
    pub fn empty(next_header_key: HeaderKey) -> Self {
        Self {
            chain: None,
            next_header_key,
        }
    }

    /// Whether this message ratchet has an established chain.
    #[cfg(any(feature = "serde", feature = "prost"))]
    pub(crate) fn has_chain(&self) -> bool {
        self.chain.is_some()
    }

    /// HeaderKey of the current chain, if there is one.
    pub fn header_key(&self) -> Option<Zeroizing<HeaderKey>> {
        self.chain
            .as_ref()
            .map(|chain| Zeroizing::new(chain.header_key))
    }

    /// Next HeaderKey, wrapped in `Zeroizing`.
    pub fn next_header_key(&self) -> Zeroizing<HeaderKey> {
        Zeroizing::new(self.next_header_key)
    }

    /// Perform ratchet step, update ChainKey, and return MessageKey; None if there is no chain yet.
    pub fn step(&mut self) -> Option<Zeroizing<MessageKey>> {
        let chain = self.chain.as_mut()?;
        let message_key = hmac_sha256(&chain.chain_key, &[1]);
        let next_chain_key = hmac_sha256(&chain.chain_key, &[2]);
        chain.chain_key.zeroize();
        chain.chain_key = *next_chain_key;
        Some(message_key)
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedMessageRatchet {
    pub(crate) fn has_chain(&self) -> bool {
        self.chain.is_some()
    }

    pub(crate) fn header_key(&self) -> Option<Zeroizing<HeaderKey>> {
        self.chain
            .as_ref()
            .map(|chain| Zeroizing::new(chain.header_key))
    }

    pub(crate) fn next_header_key(&self) -> Zeroizing<HeaderKey> {
        Zeroizing::new(self.next_header_key)
    }
}

#[cfg(feature = "prost")]
impl From<&MessageRatchet> for crate::proto::MessageRatchet {
    fn from(message_ratchet: &MessageRatchet) -> Self {
        Self {
            chain: message_ratchet
                .chain
                .as_ref()
                .map(|chain| crate::proto::Chain {
                    chain_key: chain.chain_key.to_vec(),
                    header_key: chain.header_key.to_vec(),
                }),
            next_header_key: message_ratchet.next_header_key.to_vec(),
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&crate::proto::MessageRatchet> for MessageRatchet {
    type Error = crate::error::MalformedState;

    fn try_from(message_ratchet: &crate::proto::MessageRatchet) -> Result<Self, Self::Error> {
        let chain = match &message_ratchet.chain {
            Some(chain) => {
                let chain_key = Zeroizing::new(crate::proto::key(&chain.chain_key)?);
                let header_key = Zeroizing::new(crate::proto::key(&chain.header_key)?);
                Some(Chain {
                    chain_key: *chain_key,
                    header_key: *header_key,
                })
            }
            None => None,
        };
        let next_header_key = Zeroizing::new(crate::proto::key(&message_ratchet.next_header_key)?);
        Ok(Self {
            chain,
            next_header_key: *next_header_key,
        })
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; KEY_LENGTH]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().into())
}
