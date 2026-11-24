//! Double Ratchet Algorithm.

mod dh_root;
mod message;

use core::fmt;

use dh_root::DhRootRatchet;
use message::MessageRatchet;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
use crate::error::MalformedState;
use crate::{
    error::CryptoError,
    key::{DH_KEY_LENGTH, DhPrivateKey, HeaderKey, MessageKey, SharedKeys},
};

/// Double ratchet. See the example in [`document`](crate::document).
///
/// With the `serde` or `rkyv` feature, it serializes with all its keys, and with `prost` it
/// converts to and from `proto::Ratchet`, so a session can be kept between runs: keep the output
/// secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "RatchetUnchecked")
)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    rkyv(bytecheck(verify))
)]
pub struct Ratchet {
    dh_root: DhRootRatchet,
    message_ratchet_sender: MessageRatchet,
    message_ratchet_receiver: MessageRatchet,
    /// - true: next dh step will update message_ratchet_sender
    /// - false: next dh step will update message_ratchet_receiver
    dh_step_updates_sender: bool,
}

/// Validate state-machine invariants shared across `Ratchet` and `ArchivedRatchet`.
#[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
fn validate_ratchet_invariants(
    update_private_key: bool,
    dh_step_updates_sender: bool,
    has_sender_chain: bool,
    has_receiver_chain: bool,
) -> Result<(), MalformedState> {
    if update_private_key != !dh_step_updates_sender {
        return Err(MalformedState);
    }
    if dh_step_updates_sender && !has_receiver_chain {
        return Err(MalformedState);
    }
    if !dh_step_updates_sender && !has_sender_chain && has_receiver_chain {
        return Err(MalformedState);
    }
    Ok(())
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "Ratchet")]
struct RatchetUnchecked {
    dh_root: DhRootRatchet,
    message_ratchet_sender: MessageRatchet,
    message_ratchet_receiver: MessageRatchet,
    dh_step_updates_sender: bool,
}

#[cfg(feature = "serde")]
impl TryFrom<RatchetUnchecked> for Ratchet {
    type Error = MalformedState;

    fn try_from(raw: RatchetUnchecked) -> Result<Self, Self::Error> {
        let ratchet = Self {
            dh_root: raw.dh_root,
            message_ratchet_sender: raw.message_ratchet_sender,
            message_ratchet_receiver: raw.message_ratchet_receiver,
            dh_step_updates_sender: raw.dh_step_updates_sender,
        };
        ratchet.validate()?;
        Ok(ratchet)
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedRatchet {
    /// Whether the next DH step establishes the sending chain.
    pub fn dh_step_updates_sender(&self) -> bool {
        self.dh_step_updates_sender
    }

    /// Current sending header key of the archived ratchet, if a sending chain is established.
    pub fn header_key_sender(&self) -> Option<HeaderKey> {
        self.message_ratchet_sender.header_key()
    }

    /// Current receiving header key of the archived ratchet, if a receiving chain is established.
    pub fn header_key_receiver(&self) -> Option<HeaderKey> {
        self.message_ratchet_receiver.header_key()
    }

    /// Next receiving header key of the archived ratchet.
    pub fn next_header_key_receiver(&self) -> HeaderKey {
        self.message_ratchet_receiver.next_header_key()
    }
}

#[cfg(feature = "rkyv")]
unsafe impl<C> rkyv::bytecheck::Verify<C> for ArchivedRatchet
where
    C: rkyv::rancor::Fallible + ?Sized,
    C::Error: rkyv::rancor::Source,
{
    fn verify(&self, _context: &mut C) -> Result<(), C::Error> {
        use rkyv::rancor::Source;
        validate_ratchet_invariants(
            self.dh_root.update_private_key(),
            self.dh_step_updates_sender,
            self.message_ratchet_sender.has_chain(),
            self.message_ratchet_receiver.has_chain(),
        )
        .map_err(C::Error::new)
    }
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
    /// Whether the next DH step establishes the sending chain.
    pub fn dh_step_updates_sender(&self) -> bool {
        self.dh_step_updates_sender
    }

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
        self.step_dh_root_with(public_key, &[])
    }

    /// Perform a DH-root ratchet step while mixing an additional secret (such as a post-quantum
    /// KEM shared secret) into the root-key HKDF.
    ///
    /// When `extra_secret` is empty, this is identical to [`Self::step_dh_root`]. When
    /// `extra_secret` is non-empty, the root-key HKDF mixes `DH || extra_secret` with distinct
    /// domain separation (`ratchetx2.v1/hybrid/*`).
    ///
    /// On an invalid peer public key or RNG failure, returns an error and leaves the state
    /// unchanged.
    pub fn step_dh_root_with(
        &mut self,
        public_key: &[u8],
        extra_secret: &[u8],
    ) -> Result<(), CryptoError> {
        let (chain_key, next_header_key) = self.dh_root.step_with(public_key, extra_secret)?;
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

    /// Validate internal state-machine invariants.
    #[cfg(any(feature = "serde", feature = "prost"))]
    pub(crate) fn validate(&self) -> Result<(), MalformedState> {
        validate_ratchet_invariants(
            self.dh_root.update_private_key(),
            self.dh_step_updates_sender,
            self.message_ratchet_sender.has_chain(),
            self.message_ratchet_receiver.has_chain(),
        )
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

        let restored = Self {
            dh_root: ratchet.dh_root.as_ref().ok_or(MalformedState)?.try_into()?,
            message_ratchet_sender: ratchet.sender.as_ref().ok_or(MalformedState)?.try_into()?,
            message_ratchet_receiver: ratchet
                .receiver
                .as_ref()
                .ok_or(MalformedState)?
                .try_into()?,
            dh_step_updates_sender: ratchet.dh_step_updates_sender,
        };
        restored.validate()?;
        Ok(restored)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_keys() -> SharedKeys {
        SharedKeys {
            secret_key: [1; 32],
            header_key_alice: [2; 32],
            header_key_bob: [3; 32],
        }
    }

    #[test]
    fn rejects_non_canonical_low_order_and_zero_dh_keys() {
        let keys = test_keys();
        let bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let valid_pk = bob.public_key();
        let mut alice = Ratchet::alice(&keys, &valid_pk).unwrap();
        let snapshot_pk = alice.public_key();
        let snapshot_next_hk = alice.next_header_key_receiver();

        // Non-canonical: bit 255 set on an otherwise valid public key.
        let mut high_bit = valid_pk;
        high_bit[31] |= 0x80;
        assert_eq!(Ratchet::alice(&keys, &high_bit).unwrap_err(), CryptoError);
        assert_eq!(alice.step_dh_root(&high_bit).unwrap_err(), CryptoError);

        // Non-canonical: u >= p = 2^255 - 19.
        let mut field_p = [0xFF; 32];
        field_p[31] = 0x7F;
        field_p[0] = 0xED; // u = p (== 0 mod p)
        assert_eq!(alice.step_dh_root(&field_p).unwrap_err(), CryptoError);
        field_p[0] = 0xEE; // u = p + 1
        assert_eq!(alice.step_dh_root(&field_p).unwrap_err(), CryptoError);
        field_p[0] = 0xFF; // u = 2^255 - 1
        assert_eq!(alice.step_dh_root(&field_p).unwrap_err(), CryptoError);

        // All-zero and known Curve25519 / twist low-order points.
        let low_order_keys: [[u8; 32]; 5] = [
            [0; 32],
            {
                let mut k = [0; 32];
                k[0] = 1;
                k
            },
            // p - 1 (order 2 on twist)
            {
                let mut k = [0xFF; 32];
                k[31] = 0x7F;
                k[0] = 0xEC;
                k
            },
            // Order-8 Montgomery u-coordinate
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            // Second order-8 Montgomery u-coordinate
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
        ];
        for bad in &low_order_keys {
            assert_eq!(alice.step_dh_root(bad).unwrap_err(), CryptoError);
        }

        // Wrong length rejected cleanly.
        assert_eq!(alice.step_dh_root(&[1; 31]).unwrap_err(), CryptoError);
        assert_eq!(alice.step_dh_root(&[1; 33]).unwrap_err(), CryptoError);

        // State was left completely unchanged on all errors.
        assert_eq!(alice.public_key(), snapshot_pk);
        assert_eq!(alice.next_header_key_receiver(), snapshot_next_hk);
    }

    #[test]
    fn step_dh_root_with_domain_separation_and_sync() {
        let keys = test_keys();
        let mut bob_classic = Ratchet::bob(&keys, DhPrivateKey::generate());
        let mut alice_classic = Ratchet::alice(&keys, &bob_classic.public_key()).unwrap();
        let mut bob_hybrid = bob_classic.clone();
        let mut alice_hybrid = alice_classic.clone();

        // Empty extra_secret matches classical step_dh_root bit-for-bit.
        bob_classic
            .step_dh_root(&alice_classic.public_key())
            .unwrap();
        bob_hybrid
            .step_dh_root_with(&alice_hybrid.public_key(), &[])
            .unwrap();
        assert_eq!(alice_classic, bob_classic);
        assert_eq!(alice_hybrid, bob_hybrid);
        let mk_c = bob_classic.step_message_ratchet_receiver().unwrap();
        let mk_h = bob_hybrid.step_message_ratchet_receiver().unwrap();
        assert_eq!(mk_c, mk_h);
        assert_eq!(alice_classic.step_message_ratchet_sender().unwrap(), mk_c);
        assert_eq!(alice_hybrid.step_message_ratchet_sender().unwrap(), mk_h);

        // Non-empty extra_secret keeps Alice & Bob synchronized and domain-separated from classical.
        let pq_secret = [0xA5u8; 32];
        bob_classic
            .step_dh_root(&alice_classic.public_key())
            .unwrap();
        alice_classic
            .step_dh_root(&bob_classic.public_key())
            .unwrap();

        bob_hybrid
            .step_dh_root_with(&alice_hybrid.public_key(), &pq_secret)
            .unwrap();
        alice_hybrid
            .step_dh_root_with(&bob_hybrid.public_key(), &pq_secret)
            .unwrap();
        assert_eq!(alice_hybrid, bob_hybrid);

        let mk_bob = bob_hybrid.step_message_ratchet_sender().unwrap();
        let mk_alice = alice_hybrid.step_message_ratchet_receiver().unwrap();
        assert_eq!(mk_bob, mk_alice);

        let mk_classic = bob_classic.step_message_ratchet_sender().unwrap();
        assert_ne!(mk_bob, mk_classic);
    }

    /// `ratchet` saved and restored, once through each format enabled.
    #[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
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
    #[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
    fn restored_ratchets_carry_on() {
        let keys = test_keys();
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

    #[test]
    #[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
    fn rejects_invalid_restored_invariants() {
        let keys = test_keys();
        let bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();

        #[cfg(feature = "prost")]
        {
            // Violate dh_root.update_private_key == !dh_step_updates_sender.
            let mut bad = crate::proto::Ratchet::from(&alice);
            bad.dh_step_updates_sender = !bad.dh_step_updates_sender;
            assert_eq!(Ratchet::try_from(&bad).unwrap_err(), MalformedState);

            // Violate: dh_step_updates_sender == true requires receiver.chain to be Some.
            let mut bad2 = crate::proto::Ratchet::from(&bob);
            bad2.dh_step_updates_sender = true;
            bad2.dh_root.as_mut().unwrap().update_private_key = false;
            assert_eq!(Ratchet::try_from(&bad2).unwrap_err(), MalformedState);

            // Violate: dh_step_updates_sender == false cannot have receiver Some and sender None.
            let mut bob_mid = bob.clone();
            bob_mid.step_dh_root(&alice.public_key()).unwrap();
            let mut bad3 = crate::proto::Ratchet::from(&bob_mid);
            bad3.dh_step_updates_sender = false;
            bad3.dh_root.as_mut().unwrap().update_private_key = true;
            assert_eq!(Ratchet::try_from(&bad3).unwrap_err(), MalformedState);
        }

        #[cfg(feature = "serde")]
        {
            let mut val: serde_json::Value =
                serde_json::from_str(&serde_json::to_string(&alice).unwrap()).unwrap();
            val["dh_step_updates_sender"] = serde_json::json!(true);
            assert!(serde_json::from_value::<Ratchet>(val).is_err());
        }

        #[cfg(feature = "rkyv")]
        {
            // Construct an invalid Ratchet directly and verify rkyv bytecheck rejects it.
            let mut invalid = alice.clone();
            invalid.dh_step_updates_sender = true;
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&invalid).unwrap();
            assert!(rkyv::from_bytes::<Ratchet, rkyv::rancor::Error>(&bytes).is_err());
        }
    }
}
