use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::{ChainKey, HeaderKey, KEY_LENGTH, MessageKey};

/// An established chain: its ChainKey and the HeaderKey of its messages.
#[derive(Debug, Clone, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
struct Chain {
    chain_key: ChainKey,
    header_key: HeaderKey,
}

#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
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

impl MessageRatchet {
    /// New a MessageRatchet.
    pub fn from_key(
        chain_key: ChainKey,
        header_key: HeaderKey,
        next_header_key: HeaderKey,
    ) -> Self {
        Self {
            chain: Some(Chain {
                chain_key,
                header_key,
            }),
            next_header_key,
        }
    }

    /// New a MessageRatchet without a chain yet, supposed to be only used in initialization.
    pub fn empty(next_header_key: HeaderKey) -> Self {
        Self {
            chain: None,
            next_header_key,
        }
    }

    /// HeaderKey of the current chain, if there is one.
    pub fn header_key(&self) -> Option<HeaderKey> {
        self.chain.as_ref().map(|chain| chain.header_key)
    }

    /// Perform ratchet step, update ChainKey, and return MessageKey; None if there is no chain yet.
    pub fn step(&mut self) -> Option<MessageKey> {
        let chain = self.chain.as_mut()?;
        let message_key = hmac_sha256(&chain.chain_key, &[1]);
        chain.chain_key = hmac_sha256(&chain.chain_key, &[2]);
        Some(message_key)
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
            Some(chain) => Some(Chain {
                chain_key: crate::proto::key(&chain.chain_key)?,
                header_key: crate::proto::key(&chain.header_key)?,
            }),
            None => None,
        };
        Ok(Self {
            chain,
            next_header_key: crate::proto::key(&message_ratchet.next_header_key)?,
        })
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; KEY_LENGTH] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
