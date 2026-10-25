//! Double Ratchet Algorithm.

mod dh_root;
mod message;

use core::fmt;

use dh_root::DhRootRatchet;
use message::MessageRatchet;

use crate::{
    error::CryptoError,
    key::{DH_KEY_LENGTH, DhPrivateKey, HeaderKey, MessageKey, SharedKeys},
};

/// Double ratchet. See the example in [`document`](crate::document).
///
/// With the `serde` or `rkyv` feature, it serializes with all its keys, and with `prost` it
/// converts to and from `proto::Ratchet`, so a session can be kept between runs: keep the output
/// secret.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct Ratchet {
    dh_root: DhRootRatchet,
    message_ratchet_sender: MessageRatchet,
    message_ratchet_receiver: MessageRatchet,
    /// - true: next dh step will update message_ratchet_sender
    /// - false: next dh step will update message_ratchet_receiver
    dh_step_updates_sender: bool,
}

impl fmt::Debug for Ratchet {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ratchet").finish_non_exhaustive()
    }
}

impl PartialEq for Ratchet {
    /// Alice and Bob have the same DhRootRatchet,
    /// and Alice's message sending ratchet is the same as Bob's message receiving ratchet,
    /// so is Alice's receiving ratchet and Bob's sending ratchet.
    ///
    /// So, two Ratchets A and B are Eq only if they have the same DhRootRatchet,
    /// A's sending ratchet equals B's receiving ratchet, and A's receiving ratchet equals B's
    /// sending ratchet.
    fn eq(&self, other: &Self) -> bool {
        self.dh_root == other.dh_root
            && self.message_ratchet_sender == other.message_ratchet_receiver
            && self.message_ratchet_receiver == other.message_ratchet_sender
    }
}

impl Ratchet {
    /// New a party who sends message first, from the shared `keys`.
    ///
    /// Fails if `public_key` (Bob's) is not a valid X25519 public key.
    pub fn alice(keys: &SharedKeys, public_key: &[u8]) -> Result<Self, CryptoError> {
        let mut this = Self {
            dh_root: DhRootRatchet::alice(keys.secret_key),
            message_ratchet_sender: MessageRatchet::empty(keys.header_key_alice),
            message_ratchet_receiver: MessageRatchet::empty(keys.header_key_bob),
            dh_step_updates_sender: true,
        };
        this.step_dh_root(public_key)?;
        Ok(this)
    }

    /// New a party who waits for the message first, from the shared `keys`.
    ///
    /// # Caution
    /// Bob starts without message chains: `step_dh_root` sets up the receiving chain
    /// when the first message arrives, and `step_dh_root` again sets up the sending chain.
    /// Until then, [`Self::step_message_ratchet_sender`] and
    /// [`Self::step_message_ratchet_receiver`] return `None`.
    pub fn bob(keys: &SharedKeys, private_key: DhPrivateKey) -> Self {
        Self {
            dh_root: DhRootRatchet::bob(keys.secret_key, private_key),
            message_ratchet_sender: MessageRatchet::empty(keys.header_key_bob),
            message_ratchet_receiver: MessageRatchet::empty(keys.header_key_alice),
            dh_step_updates_sender: false,
        }
    }

    /// Get current public key.
    pub fn public_key(&self) -> [u8; DH_KEY_LENGTH] {
        self.dh_root.public_key()
    }

    /// Get current message sending HeaderKey; None until the sending chain is set up.
    pub fn header_key_sender(&self) -> Option<HeaderKey> {
        self.message_ratchet_sender.header_key()
    }

    /// Get current message receiving HeaderKey; None until the receiving chain is set up.
    pub fn header_key_receiver(&self) -> Option<HeaderKey> {
        self.message_ratchet_receiver.header_key()
    }

    /// Get next message receiving HeaderKey.
    /// Classically, if failed with current HeaderKey when decrypting enc-header,
    /// one should try next HeaderKey, if succeed, do DhRootRatchet step and cache MessageKey
    /// for future (for it's message out of order).
    pub fn next_header_key_receiver(&self) -> HeaderKey {
        self.message_ratchet_receiver.next_header_key
    }

    /// Perform ratchet step on message sending ratchet.
    /// Updating message sending ratchet's ChainKey, and return MessageKey;
    /// None until the sending chain is set up.
    pub fn step_message_ratchet_sender(&mut self) -> Option<MessageKey> {
        self.message_ratchet_sender.step()
    }

    /// Perform ratchet step on message receiving ratchet.
    /// Update message receiving ratchet's ChainKey, and return MessageKey;
    /// None until the receiving chain is set up.
    pub fn step_message_ratchet_receiver(&mut self) -> Option<MessageKey> {
        self.message_ratchet_receiver.step()
    }

    /// Perform ratchet step on DH-Root ratchet.
    /// Update DH pair if needed, update root key, and update **one of** message ratchets.
    ///
    /// # Caution
    /// In the Signal document, one dh-root step will update both message sending and receiving chain,
    /// however, notice that, when initialize Alice, only message sending chain is updated,
    /// so in this implementation, dh-root step will update message sending and receiving chain in rotation.
    ///
    /// In other words, dh-root should step twice when receiving next-header-key encrypted header.
    ///
    /// Additionally, by doing so, it's more convenient to check whether states of parties are matching
    /// when writing tests.
    ///
    /// On an invalid peer public key, returns an error and leaves the state unchanged.
    pub fn step_dh_root(&mut self, public_key: &[u8]) -> Result<(), CryptoError> {
        let (chain_key, next_header_key) = self.dh_root.step(public_key)?;
        match self.dh_step_updates_sender {
            true => {
                self.message_ratchet_sender = MessageRatchet::from_key(
                    chain_key,
                    self.message_ratchet_sender.next_header_key,
                    next_header_key,
                )
            }
            false => {
                self.message_ratchet_receiver = MessageRatchet::from_key(
                    chain_key,
                    self.message_ratchet_receiver.next_header_key,
                    next_header_key,
                )
            }
        }
        self.dh_step_updates_sender = !self.dh_step_updates_sender;
        Ok(())
    }
}

#[cfg(feature = "prost")]
impl From<&Ratchet> for crate::proto::Ratchet {
    fn from(ratchet: &Ratchet) -> Self {
        Self {
            dh_root: Some((&ratchet.dh_root).into()),
            sender: Some((&ratchet.message_ratchet_sender).into()),
            receiver: Some((&ratchet.message_ratchet_receiver).into()),
            dh_step_updates_sender: ratchet.dh_step_updates_sender,
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&crate::proto::Ratchet> for Ratchet {
    type Error = crate::error::MalformedState;

    fn try_from(ratchet: &crate::proto::Ratchet) -> Result<Self, Self::Error> {
        use crate::error::MalformedState;

        Ok(Self {
            dh_root: ratchet.dh_root.as_ref().ok_or(MalformedState)?.try_into()?,
            message_ratchet_sender: ratchet.sender.as_ref().ok_or(MalformedState)?.try_into()?,
            message_ratchet_receiver: ratchet
                .receiver
                .as_ref()
                .ok_or(MalformedState)?
                .try_into()?,
            dh_step_updates_sender: ratchet.dh_step_updates_sender,
        })
    }
}

#[cfg(all(test, any(feature = "serde", feature = "rkyv", feature = "prost")))]
mod test {
    use super::*;

    /// `ratchet` saved and restored, once through each format enabled.
    fn restored(ratchet: &Ratchet) -> Vec<Ratchet> {
        Vec::from([
            #[cfg(feature = "serde")]
            serde_json::from_str(&serde_json::to_string(ratchet).unwrap()).unwrap(),
            #[cfg(feature = "rkyv")]
            rkyv::from_bytes::<_, rkyv::rancor::Error>(
                &rkyv::to_bytes::<rkyv::rancor::Error>(ratchet).unwrap(),
            )
            .unwrap(),
            #[cfg(feature = "prost")]
            Ratchet::try_from(&crate::proto::Ratchet::from(ratchet)).unwrap(),
        ])
    }

    #[test]
    fn restored_ratchets_carry_on() {
        let keys = SharedKeys {
            secret_key: [1; 32],
            header_key_alice: [2; 32],
            header_key_bob: [3; 32],
        };
        let mut bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();
        // Bob's chains are still unset.
        for restored in restored(&bob) {
            assert_eq!(restored.header_key_sender(), None);
            assert_eq!(restored.header_key_receiver(), None);
        }

        bob.step_dh_root(&alice.public_key()).unwrap();
        for (mut alice, mut bob) in restored(&alice).into_iter().zip(restored(&bob)) {
            assert_eq!(alice, bob);
            // So is which chain the next steps update, and with which keys.
            bob.step_dh_root(&alice.public_key()).unwrap();
            alice.step_dh_root(&bob.public_key()).unwrap();
            assert_eq!(alice, bob);
        }
    }
}
