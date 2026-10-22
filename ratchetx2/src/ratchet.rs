//! Double Ratchet Algorithm.

mod dh_root;
mod message;

use dh_root::DhRootRatchet;
use message::MessageRatchet;

use crate::error::CryptoError;
use crate::key::{DhPrivateKey, HeaderKey, MessageKey, SecretKey};

/// Double ratchet.
/// # Example
/// ```
/// use ratchetx2::{DhPrivateKey, SharedKeys};
///
/// let shared_keys = SharedKeys {
///     secret_key: [0; 32],
///     header_key_alice: [1; 32],
///     header_key_bob: [2; 32],
/// };
/// let mut bob = shared_keys.bob(DhPrivateKey::generate());
/// let mut alice = shared_keys.alice(&bob.public_key()).unwrap();
/// // Bob has no sending chain until he has received from Alice.
/// assert_eq!(bob.step_msgs(), None);
///
/// bob.step_dh_root(&alice.public_key()).unwrap();
/// assert_eq!(alice, bob); // Alice and Bob have the "same" state
/// assert_eq!(alice.step_msgs().unwrap(), bob.step_msgr().unwrap()); // returning the same message key
/// assert_eq!(alice.step_msgs().unwrap(), bob.step_msgr().unwrap());
///
/// bob.step_dh_root(&alice.public_key()).unwrap();
/// alice.step_dh_root(&bob.public_key()).unwrap();
/// assert_eq!(alice, bob);
/// assert_eq!(bob.step_msgs().unwrap(), alice.step_msgr().unwrap());
/// assert_eq!(bob.step_msgs().unwrap(), alice.step_msgr().unwrap());
///
/// alice.step_dh_root(&bob.public_key()).unwrap();
/// bob.step_dh_root(&alice.public_key()).unwrap();
/// assert_eq!(alice, bob);
/// assert_eq!(alice.step_msgs().unwrap(), bob.step_msgr().unwrap());
/// assert_eq!(alice.step_msgs().unwrap(), bob.step_msgr().unwrap());
/// ```
#[derive(Debug, Clone)]
pub struct Ratchet {
    dh_root: DhRootRatchet,
    msgs: MessageRatchet,
    msgr: MessageRatchet,
    /// - true: next dh step will update msgs
    /// - false: next dh step will update msgr
    dh_step_s: bool,
}

impl PartialEq for Ratchet {
    /// Alice and Bob have the same DhRootRatchet,
    /// and Alice's message sending ratchet is the same as Bob's message receiving ratchet,
    /// so is Alice's receiving ratchet and Bob's sending ratchet.
    ///
    /// So, two Ratchets A and B are Eq only if they have the same DhRootRatchet,
    /// and A.msgs == B.msgr && A.msgr == B.msgs.
    fn eq(&self, other: &Self) -> bool {
        self.dh_root == other.dh_root && self.msgs == other.msgr && self.msgr == other.msgs
    }
}

impl Ratchet {
    /// New a party who sends message first.
    ///
    /// # Args
    /// - secret_key, header_key_alice, header_key_bob: shared keys for initialization
    ///
    /// Fails if `public_key` (Bob's) is not a valid X25519 public key.
    pub fn alice(
        secret_key: SecretKey,
        public_key: &[u8],
        header_key_alice: HeaderKey,
        header_key_bob: HeaderKey,
    ) -> Result<Self, CryptoError> {
        let mut this = Self {
            dh_root: DhRootRatchet::alice(secret_key),
            msgs: MessageRatchet::empty(header_key_alice),
            msgr: MessageRatchet::empty(header_key_bob),
            dh_step_s: true,
        };
        this.step_dh_root(public_key)?;
        Ok(this)
    }

    /// New a party who waits for the message first.
    ///
    /// # Args
    /// - secret_key, header_key_alice, header_key_bob: shared keys for initialization
    ///
    /// # Caution
    /// Bob starts without message chains: `step_dh_root` sets up the receiving chain
    /// when the first message arrives, and `step_dh_root` again sets up the sending chain.
    /// Until then, [`Self::step_msgs`] and [`Self::step_msgr`] return `None`.
    pub fn bob(
        secret_key: SecretKey,
        private_key: DhPrivateKey,
        header_key_alice: HeaderKey,
        header_key_bob: HeaderKey,
    ) -> Self {
        Self {
            dh_root: DhRootRatchet::bob(secret_key, private_key),
            msgs: MessageRatchet::empty(header_key_bob),
            msgr: MessageRatchet::empty(header_key_alice),
            dh_step_s: false,
        }
    }

    /// Get current public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.dh_root.public_key()
    }

    /// Get current message sending HeaderKey; None until the sending chain is set up.
    pub fn header_key_s(&self) -> Option<HeaderKey> {
        self.msgs.header_key()
    }

    /// Get current message receiving HeaderKey; None until the receiving chain is set up.
    pub fn header_key_r(&self) -> Option<HeaderKey> {
        self.msgr.header_key()
    }

    /// Get next message receiving HeaderKey.
    /// Classically, if failed with current HeaderKey when decrypting enc-header,
    /// one should try next HeaderKey, if succeed, do DhRootRatchet step and cache MessageKey
    /// for future (for it's message out of order).
    pub fn next_header_key_r(&self) -> HeaderKey {
        self.msgr.next_header_key
    }

    /// Perform ratchet step on message sending ratchet.
    /// Updating message sending ratchet's ChainKey, and return MessageKey;
    /// None until the sending chain is set up.
    pub fn step_msgs(&mut self) -> Option<MessageKey> {
        self.msgs.step()
    }

    /// Perform ratchet step on message receiving ratchet.
    /// Update message receiving ratchet's ChainKey, and return MessageKey;
    /// None until the receiving chain is set up.
    pub fn step_msgr(&mut self) -> Option<MessageKey> {
        self.msgr.step()
    }

    /// Perform ratchet step on DH-Root ratchet.
    /// Update DH pair if needed, update root key, and update **one of** message ratchets.
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
        match self.dh_step_s {
            true => {
                self.msgs =
                    MessageRatchet::from_key(chain_key, self.msgs.next_header_key, next_header_key)
            }
            false => {
                self.msgr =
                    MessageRatchet::from_key(chain_key, self.msgr.next_header_key, next_header_key)
            }
        }
        self.dh_step_s = !self.dh_step_s;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::SharedKeys;

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
        let bob = keys.bob(DhPrivateKey::generate());
        let alice = keys.alice(&bob.public_key()).unwrap();
        assert!(alice.header_key_s().is_some());
        assert_eq!(alice.header_key_r(), None);
        assert_eq!(bob.header_key_s(), None);
        assert_eq!(bob.header_key_r(), None);
    }

    #[test]
    fn invalid_peer_key_leaves_state_unchanged() {
        let keys = shared_keys();
        assert!(keys.alice(&[0; 32]).is_err());
        let bob = keys.bob(DhPrivateKey::generate());
        let mut alice = keys.alice(&bob.public_key()).unwrap();
        let before = alice.clone();
        // A low-order point and a wrong-length key.
        assert!(alice.step_dh_root(&[0; 32]).is_err());
        assert!(alice.step_dh_root(&[9; 31]).is_err());
        assert!(alice.dh_root == before.dh_root);
        assert!(alice.msgs == before.msgs && alice.msgr == before.msgr);
        assert_eq!(alice.dh_step_s, before.dh_step_s);
    }
}
