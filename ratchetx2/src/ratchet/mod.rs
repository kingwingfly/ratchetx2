//! Double Ratchet Algorithm.

mod dh_root;
mod message;

use dh_root::DhRootRatchet;
use message::MessageRatchet;

use crate::key::{HeaderKey, MessageKey, SecretKey};

/// Double ratchet
/// # Example
/// ```
/// use ratchetx2::SharedKeys;
///
/// let shared_keys = SharedKeys {
///     secret_key: [0; 32],
///     header_key_alice: [1; 32],
///     header_key_bob: [2; 32],
/// };
/// let mut bob = shared_keys.bob();
/// let mut alice = shared_keys.alice(bob.public_key());
///
/// bob.step_dh_root(alice.public_key());
/// assert_eq!(alice, bob);
/// assert_eq!(alice.step_msgs(), bob.step_msgr()); // returning the same message key
/// assert_eq!(alice.step_msgs(), bob.step_msgr());
///
/// bob.step_dh_root(alice.public_key());
/// alice.step_dh_root(bob.public_key());
/// assert_eq!(alice, bob);
/// assert_eq!(bob.step_msgs(), alice.step_msgr());
/// assert_eq!(bob.step_msgs(), alice.step_msgr());
///
/// alice.step_dh_root(bob.public_key());
/// bob.step_dh_root(alice.public_key());
/// assert_eq!(alice, bob);
/// assert_eq!(alice.step_msgs(), bob.step_msgr());
/// assert_eq!(alice.step_msgs(), bob.step_msgr());
/// ```
#[derive(Debug)]
pub struct Ratchetx2 {
    dh_root: DhRootRatchet,
    msgs: MessageRatchet,
    msgr: MessageRatchet,
    /// - true: next dh step will update msgs
    /// - false: next dh step will update msgr
    dh_step_s: bool,
}

impl PartialEq for Ratchetx2 {
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

impl Ratchetx2 {
    /// New a party who sends message first.
    /// # Args
    /// - secret_key, header_key_alice, header_key_bob: shared keys for initialization
    pub fn alice(
        secret_key: SecretKey,
        public_key: impl AsRef<[u8]>,
        header_key_alice: HeaderKey,
        header_key_bob: HeaderKey,
    ) -> Self {
        let mut this = Self {
            dh_root: DhRootRatchet::alice(secret_key),
            msgs: MessageRatchet::empty(header_key_alice),
            msgr: MessageRatchet::empty(header_key_bob),
            dh_step_s: true,
        };
        this.step_dh_root(public_key);
        this
    }

    /// New a party who waits for the message first.
    /// # Args
    /// - secret_key, header_key_alice, header_key_bob: shared keys for initialization
    ///
    /// # Caution
    /// Bob is initialized with [0; 32] as message key and header key, therefore,
    /// step_dh_root to update message receiving chain before first receiving,
    /// and step_dh_root again before first sending.
    pub fn bob(
        secret_key: SecretKey,
        header_key_alice: HeaderKey,
        header_key_bob: HeaderKey,
    ) -> Self {
        Self {
            dh_root: DhRootRatchet::bob(secret_key),
            msgs: MessageRatchet::empty(header_key_bob),
            msgr: MessageRatchet::empty(header_key_alice),
            dh_step_s: false,
        }
    }

    /// Get current public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.dh_root.public_key()
    }

    /// Get current message sending HeaderKey.
    pub fn header_key_s(&self) -> HeaderKey {
        self.msgs.header_key
    }

    /// Get current message receiving HeaderKey.
    pub fn header_key_r(&self) -> HeaderKey {
        self.msgr.header_key
    }

    /// Get next message receiving HeaderKey.
    /// Classically, if failed with current HeaderKey when decrypting enc-header,
    /// one should try next HeaderKey, if succeed, do DhRootRatchet step and cache MessageKey
    /// for future (for it's message out of order).
    pub fn next_header_key_r(&self) -> HeaderKey {
        self.msgr.next_header_key
    }

    /// Perform ratchet step on message sending ratchet.
    /// Updating message sending ratchet's ChainKey, and return MessageKey.
    pub fn step_msgs(&mut self) -> MessageKey {
        self.msgs.step()
    }

    /// Perform ratchet step on message receiving ratchet.
    /// Update message receiving ratchet's ChainKey, and return MessageKey.
    pub fn step_msgr(&mut self) -> MessageKey {
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
    pub fn step_dh_root(&mut self, public_key: impl AsRef<[u8]>) {
        let (chain_key, next_header_key) = self.dh_root.step(public_key);
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
    }
}
