mod dh_root;
mod message;

use dh_root::DhRootRatchet;
use message::MessageRatchet;
use ring::agreement::{PublicKey, UnparsedPublicKey};

use crate::key::{HeaderKey, MessageKey, SecretKey};

/// Double ratchet
#[derive(Debug)]
pub struct Ratchetx2 {
    dh_root: DhRootRatchet,
    msgs: MessageRatchet,
    msgr: MessageRatchet,
    /// - true: next dh step will update msgs
    /// - false: next dh step will update msgr
    dh_step_s: bool,
}

#[cfg(debug_assertions)]
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
        header_key_alice: HeaderKey,
        header_key_bob: HeaderKey,
    ) -> Self {
        Self {
            dh_root: DhRootRatchet::alice(secret_key),
            msgs: MessageRatchet::empty(header_key_alice),
            msgr: MessageRatchet::empty(header_key_bob),
            dh_step_s: true,
        }
    }

    /// New a party who waits for the message first.
    /// # Args
    /// - secret_key, header_key_alice, header_key_bob: shared keys for initialization
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

    /// Get current public key
    pub fn public_key(&self) -> UnparsedPublicKey<PublicKey> {
        self.dh_root.public_key()
    }

    /// Perform ratchet step on message sending retchet
    pub fn step_msgs(&mut self) -> MessageKey {
        self.msgs.step()
    }

    /// Perform ratchet step on message receiving retchet
    pub fn step_msgr(&mut self) -> MessageKey {
        self.msgr.step()
    }

    /// Perform ratchet step on DH-Root retchet
    pub fn step_dh_root(&mut self, public_key: UnparsedPublicKey<PublicKey>) {
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
