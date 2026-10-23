//! Double Ratchet Algorithm.

mod dh_root;
mod message;

use core::fmt;

use dh_root::DhRootRatchet;
use message::MessageRatchet;

use crate::error::CryptoError;
use crate::key::{DH_KEY_LENGTH, DhPrivateKey, HeaderKey, MessageKey, SharedKeys};

/// Double ratchet. See the example in [`document`](crate::document).
#[derive(Clone)]
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

#[cfg(test)]
mod test {
    use super::*;

    fn shared_keys() -> SharedKeys {
        SharedKeys {
            secret_key: [0; 32],
            header_key_alice: [1; 32],
            header_key_bob: [2; 32],
        }
    }

    #[test]
    fn chains_start_unset() {
        let keys = shared_keys();
        let bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();
        assert!(alice.header_key_sender().is_some());
        assert_eq!(alice.header_key_receiver(), None);
        assert_eq!(bob.header_key_sender(), None);
        assert_eq!(bob.header_key_receiver(), None);
    }

    #[test]
    fn invalid_peer_key_leaves_state_unchanged() {
        let keys = shared_keys();
        assert!(Ratchet::alice(&keys, &[0; 32]).is_err());
        let bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let mut alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();
        let before = alice.clone();
        // A low-order point and a wrong-length key.
        assert!(alice.step_dh_root(&[0; 32]).is_err());
        assert!(alice.step_dh_root(&[9; 31]).is_err());
        assert!(alice.dh_root == before.dh_root);
        assert!(
            alice.message_ratchet_sender == before.message_ratchet_sender
                && alice.message_ratchet_receiver == before.message_ratchet_receiver
        );
        assert_eq!(alice.dh_step_updates_sender, before.dh_step_updates_sender);
    }
}
