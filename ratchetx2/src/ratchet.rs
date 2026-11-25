//! Double Ratchet Algorithm.

mod dh_root;
mod message;

use core::fmt;

use dh_root::DhRootRatchet;
use message::MessageRatchet;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
use crate::error::MalformedState;
use crate::{
    error::CryptoError,
    key::{DH_KEY_LENGTH, DhPrivateKey, HeaderKey, MessageKey, SharedKeys},
};

/// Which message chain the next DH-root ratchet step establishes.
///
/// Unifies the previously coupled `dh_step_updates_sender` and `dh_root.update_private_key`
/// flags so inconsistent boolean combinations are unrepresentable in memory:
/// - [`NextStep::UpdateSender`]: next DH step updates the sending chain without rotating the
///   local DH private key.
/// - [`NextStep::UpdateReceiver`]: next DH step updates the receiving chain and rotates the
///   local DH private key afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
enum NextStep {
    UpdateSender,
    UpdateReceiver,
}

impl NextStep {
    #[cfg(any(feature = "serde", feature = "prost"))]
    const fn from_updates_sender(updates_sender: bool) -> Self {
        if updates_sender {
            Self::UpdateSender
        } else {
            Self::UpdateReceiver
        }
    }

    const fn updates_sender(self) -> bool {
        matches!(self, Self::UpdateSender)
    }

    const fn rotates_private_key(self) -> bool {
        matches!(self, Self::UpdateReceiver)
    }

    const fn flip(self) -> Self {
        match self {
            Self::UpdateSender => Self::UpdateReceiver,
            Self::UpdateReceiver => Self::UpdateSender,
        }
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedNextStep {
    const fn to_next_step(&self) -> NextStep {
        match self {
            Self::UpdateSender => NextStep::UpdateSender,
            Self::UpdateReceiver => NextStep::UpdateReceiver,
        }
    }
}

/// Double ratchet. See the example in [`document`](crate::document).
///
/// With the `serde` or `rkyv` feature, it serializes with all its keys, and with `prost` it
/// converts to and from `proto::Ratchet`, so a session can be kept between runs: keep the output
/// secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    rkyv(bytecheck(verify))
)]
pub struct Ratchet {
    dh_root: DhRootRatchet,
    message_ratchet_sender: MessageRatchet,
    message_ratchet_receiver: MessageRatchet,
    #[zeroize(skip)]
    next_step: NextStep,
}

/// Validate chain-presence invariants shared across `Ratchet` and `ArchivedRatchet`.
#[cfg(any(feature = "serde", feature = "rkyv", feature = "prost"))]
fn validate_chain_invariants(
    next_step: NextStep,
    has_sender_chain: bool,
    has_receiver_chain: bool,
) -> Result<(), MalformedState> {
    match next_step {
        NextStep::UpdateSender if !has_receiver_chain => Err(MalformedState),
        NextStep::UpdateReceiver if !has_sender_chain && has_receiver_chain => Err(MalformedState),
        _ => Ok(()),
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize)]
#[serde(rename = "Ratchet")]
struct RatchetWireRef<'a> {
    dh_root: dh_root::DhRootRatchetWireRef<'a>,
    message_ratchet_sender: &'a MessageRatchet,
    message_ratchet_receiver: &'a MessageRatchet,
    dh_step_updates_sender: bool,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "Ratchet")]
struct RatchetUnchecked {
    dh_root: dh_root::DhRootRatchetWire,
    message_ratchet_sender: MessageRatchet,
    message_ratchet_receiver: MessageRatchet,
    dh_step_updates_sender: bool,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ratchet {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = RatchetWireRef {
            dh_root: self.dh_root.as_wire(self.next_step.rotates_private_key()),
            message_ratchet_sender: &self.message_ratchet_sender,
            message_ratchet_receiver: &self.message_ratchet_receiver,
            dh_step_updates_sender: self.next_step.updates_sender(),
        };
        wire.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ratchet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RatchetUnchecked::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl TryFrom<RatchetUnchecked> for Ratchet {
    type Error = MalformedState;

    fn try_from(raw: RatchetUnchecked) -> Result<Self, Self::Error> {
        let (dh_root, update_private_key) = DhRootRatchet::from_wire(raw.dh_root);
        if update_private_key != !raw.dh_step_updates_sender {
            return Err(MalformedState);
        }
        let ratchet = Self {
            dh_root,
            message_ratchet_sender: raw.message_ratchet_sender,
            message_ratchet_receiver: raw.message_ratchet_receiver,
            next_step: NextStep::from_updates_sender(raw.dh_step_updates_sender),
        };
        ratchet.validate()?;
        Ok(ratchet)
    }
}

#[cfg(feature = "rkyv")]
impl ArchivedRatchet {
    /// Whether the next DH step establishes the sending chain.
    pub fn dh_step_updates_sender(&self) -> bool {
        self.next_step.to_next_step().updates_sender()
    }

    /// Current sending header key of the archived ratchet, if a sending chain is established.
    pub fn header_key_sender(&self) -> Option<Zeroizing<HeaderKey>> {
        self.message_ratchet_sender.header_key()
    }

    /// Current receiving header key of the archived ratchet, if a receiving chain is established.
    pub fn header_key_receiver(&self) -> Option<Zeroizing<HeaderKey>> {
        self.message_ratchet_receiver.header_key()
    }

    /// Next receiving header key of the archived ratchet.
    pub fn next_header_key_receiver(&self) -> Zeroizing<HeaderKey> {
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
        validate_chain_invariants(
            self.next_step.to_next_step(),
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
    /// Standard reflexive, constant-time fieldwise equality between two ratchet states.
    ///
    /// To check whether Alice and Bob hold complementary paired states, use
    /// [`Ratchet::is_paired_with`].
    fn eq(&self, other: &Self) -> bool {
        self.next_step == other.next_step
            && self.dh_root == other.dh_root
            && self.message_ratchet_sender == other.message_ratchet_sender
            && self.message_ratchet_receiver == other.message_ratchet_receiver
    }
}

impl Eq for Ratchet {}

impl Ratchet {
    /// Whether `self` and `peer` are synchronized complementary sides of the same ratchet:
    /// matching root key, opposite next-step roles, and `self`'s sending/receiving message
    /// chains matching `peer`'s receiving/sending chains respectively.
    pub fn is_paired_with(&self, peer: &Self) -> bool {
        self.next_step != peer.next_step
            && bool::from(self.dh_root.root_key_ct_eq(&peer.dh_root))
            && self.message_ratchet_sender == peer.message_ratchet_receiver
            && self.message_ratchet_receiver == peer.message_ratchet_sender
    }

    /// Whether the next DH step establishes the sending chain.
    pub fn dh_step_updates_sender(&self) -> bool {
        self.next_step.updates_sender()
    }

    /// New a party who sends message first, from the shared `keys`.
    ///
    /// Fails if `public_key` (Bob's) is not a valid X25519 public key.
    pub fn alice(keys: &SharedKeys, public_key: &[u8]) -> Result<Self, CryptoError> {
        let mut this = Self {
            dh_root: DhRootRatchet::alice(keys.secret_key),
            message_ratchet_sender: MessageRatchet::empty(keys.header_key_alice),
            message_ratchet_receiver: MessageRatchet::empty(keys.header_key_bob),
            next_step: NextStep::UpdateSender,
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
            next_step: NextStep::UpdateReceiver,
        }
    }

    /// Get current public key.
    pub fn public_key(&self) -> [u8; DH_KEY_LENGTH] {
        self.dh_root.public_key()
    }

    /// Get current message sending HeaderKey; None until the sending chain is set up.
    pub fn header_key_sender(&self) -> Option<Zeroizing<HeaderKey>> {
        self.message_ratchet_sender.header_key()
    }

    /// Get current message receiving HeaderKey; None until the receiving chain is set up.
    pub fn header_key_receiver(&self) -> Option<Zeroizing<HeaderKey>> {
        self.message_ratchet_receiver.header_key()
    }

    /// Get next message receiving HeaderKey.
    /// Classically, if failed with current HeaderKey when decrypting enc-header,
    /// one should try next HeaderKey, if succeed, do DhRootRatchet step and cache MessageKey
    /// for future (for it's message out of order).
    pub fn next_header_key_receiver(&self) -> Zeroizing<HeaderKey> {
        self.message_ratchet_receiver.next_header_key()
    }

    /// Perform ratchet step on message sending ratchet.
    /// Updating message sending ratchet's ChainKey, and return MessageKey;
    /// None until the sending chain is set up.
    pub fn step_message_ratchet_sender(&mut self) -> Option<Zeroizing<MessageKey>> {
        self.message_ratchet_sender.step()
    }

    /// Perform ratchet step on message receiving ratchet.
    /// Update message receiving ratchet's ChainKey, and return MessageKey;
    /// None until the receiving chain is set up.
    pub fn step_message_ratchet_receiver(&mut self) -> Option<Zeroizing<MessageKey>> {
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
        let (chain_key, next_header_key) = self.dh_root.step_with(
            public_key,
            extra_secret,
            self.next_step.rotates_private_key(),
        )?;
        match self.next_step {
            NextStep::UpdateSender => {
                self.message_ratchet_sender = MessageRatchet::from_key(
                    chain_key,
                    self.message_ratchet_sender.next_header_key,
                    next_header_key,
                )
            }
            NextStep::UpdateReceiver => {
                self.message_ratchet_receiver = MessageRatchet::from_key(
                    chain_key,
                    self.message_ratchet_receiver.next_header_key,
                    next_header_key,
                )
            }
        }
        self.next_step = self.next_step.flip();
        Ok(())
    }

    /// Validate internal state-machine invariants.
    #[cfg(any(feature = "serde", feature = "prost"))]
    pub(crate) fn validate(&self) -> Result<(), MalformedState> {
        validate_chain_invariants(
            self.next_step,
            self.message_ratchet_sender.has_chain(),
            self.message_ratchet_receiver.has_chain(),
        )
    }
}

#[cfg(feature = "prost")]
impl From<&Ratchet> for crate::proto::Ratchet {
    fn from(ratchet: &Ratchet) -> Self {
        Self {
            dh_root: Some(
                ratchet
                    .dh_root
                    .to_proto(ratchet.next_step.rotates_private_key()),
            ),
            sender: Some((&ratchet.message_ratchet_sender).into()),
            receiver: Some((&ratchet.message_ratchet_receiver).into()),
            dh_step_updates_sender: ratchet.next_step.updates_sender(),
        }
    }
}

#[cfg(feature = "prost")]
impl TryFrom<&crate::proto::Ratchet> for Ratchet {
    type Error = crate::error::MalformedState;

    fn try_from(ratchet: &crate::proto::Ratchet) -> Result<Self, Self::Error> {
        use crate::error::MalformedState;

        let (dh_root, update_private_key) =
            DhRootRatchet::from_proto(ratchet.dh_root.as_ref().ok_or(MalformedState)?)?;
        if update_private_key != !ratchet.dh_step_updates_sender {
            return Err(MalformedState);
        }
        let restored = Self {
            dh_root,
            message_ratchet_sender: ratchet.sender.as_ref().ok_or(MalformedState)?.try_into()?,
            message_ratchet_receiver: ratchet
                .receiver
                .as_ref()
                .ok_or(MalformedState)?
                .try_into()?,
            next_step: NextStep::from_updates_sender(ratchet.dh_step_updates_sender),
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
    fn shared_keys_from_secret_kat() {
        let derived = SharedKeys::from_secret(&[0x42; 32]);
        // Verify deterministic HKDF-SHA256 derivation against independent extraction/expansion.
        let (_, hkdf) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&[0u8; 32]), &[0x42u8; 32]);
        let mut expected = [0u8; 96];
        hkdf.expand(b"ratchetx2.v1", &mut expected).unwrap();
        assert_eq!(derived.secret_key, expected[0..32]);
        assert_eq!(derived.header_key_alice, expected[32..64]);
        assert_eq!(derived.header_key_bob, expected[64..96]);
        // Distinct keys from distinct inputs.
        let other = SharedKeys::from_secret(&[0x43; 32]);
        assert_ne!(derived.secret_key, other.secret_key);
    }

    #[test]
    fn partial_eq_is_reflexive_and_is_paired_with_checks_peer_complement() {
        let keys = test_keys();
        let mut bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();

        // Standard reflexivity on Ratchet.
        assert_eq!(alice, alice);
        assert_eq!(bob, bob);
        assert_ne!(alice, bob);
        assert!(!alice.is_paired_with(&alice));
        assert!(!alice.is_paired_with(&bob));

        // After Bob receives Alice's first message, they are paired (complementary, not equal).
        bob.step_dh_root(&alice.public_key()).unwrap();
        assert_eq!(bob, bob);
        assert_ne!(alice, bob);
        assert!(alice.is_paired_with(&bob));
        assert!(bob.is_paired_with(&alice));

        // Unrelated session with different root key is NOT paired.
        let other_keys = SharedKeys::from_secret(&[0x99; 32]);
        let other_bob = Ratchet::bob(&other_keys, DhPrivateKey::generate());
        assert!(!alice.is_paired_with(&other_bob));
    }

    #[test]
    fn multi_turn_ratchet_derives_matching_keys() {
        let keys = SharedKeys::from_secret(&[0x11; 32]);
        let mut bob = Ratchet::bob(&keys, DhPrivateKey::generate());
        let mut alice = Ratchet::alice(&keys, &bob.public_key()).unwrap();

        // Turn 0: Alice -> Bob
        bob.step_dh_root(&alice.public_key()).unwrap();
        assert!(alice.is_paired_with(&bob));
        assert_eq!(alice.header_key_sender(), bob.header_key_receiver());
        for _ in 0..3 {
            assert_eq!(
                alice.step_message_ratchet_sender().unwrap(),
                bob.step_message_ratchet_receiver().unwrap()
            );
        }

        // Subsequent alternating turns: Bob -> Alice -> Bob -> Alice
        for turn in 0..4 {
            let (sender, receiver) = if turn % 2 == 0 {
                (&mut bob, &mut alice)
            } else {
                (&mut alice, &mut bob)
            };
            let peer_pub = receiver.public_key();
            sender.step_dh_root(&peer_pub).unwrap();
            let sender_pub = sender.public_key();
            receiver.step_dh_root(&sender_pub).unwrap();
            assert!(sender.is_paired_with(receiver));
            assert_eq!(sender.header_key_sender(), receiver.header_key_receiver());
            for _ in 0..2 {
                assert_eq!(
                    sender.step_message_ratchet_sender().unwrap(),
                    receiver.step_message_ratchet_receiver().unwrap()
                );
            }
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
        let mut bob_empty = bob_classic.clone();

        // Empty extra_secret matches classical step_dh_root bit-for-bit on the exact same DH input.
        bob_classic
            .step_dh_root(&alice_classic.public_key())
            .unwrap();
        bob_empty
            .step_dh_root_with(&alice_classic.public_key(), &[])
            .unwrap();
        assert!(alice_classic.is_paired_with(&bob_classic));
        assert!(alice_classic.is_paired_with(&bob_empty));
        let mk_c = bob_classic.step_message_ratchet_receiver().unwrap();
        let mk_e = bob_empty.step_message_ratchet_receiver().unwrap();
        assert_eq!(mk_c, mk_e);
        assert_eq!(alice_classic.step_message_ratchet_sender().unwrap(), mk_c);

        // Clone AFTER Bob's initial receiving step so every branch starts from the EXACT same
        // DH keypairs (and Bob's send step does NOT rotate his DH private key).
        let mut bob_hybrid = bob_classic.clone();
        let mut alice_hybrid = alice_classic.clone();
        let mut bob_hybrid_other = bob_classic.clone();
        assert_eq!(bob_classic.public_key(), bob_hybrid.public_key());

        let pq_secret = [0xA5u8; 32];
        let other_pq_secret = [0x5Au8; 32];

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
        assert!(alice_hybrid.is_paired_with(&bob_hybrid));

        bob_hybrid_other
            .step_dh_root_with(&alice_hybrid.public_key(), &other_pq_secret)
            .unwrap();

        // All three branches used the identical DH pair (bob_classic.public_key() == bob_hybrid.public_key()).
        assert_eq!(bob_classic.public_key(), bob_hybrid.public_key());
        assert_eq!(bob_classic.public_key(), bob_hybrid_other.public_key());

        let mk_bob = bob_hybrid.step_message_ratchet_sender().unwrap();
        let mk_alice = alice_hybrid.step_message_ratchet_receiver().unwrap();
        assert_eq!(mk_bob, mk_alice);

        let mk_classic = bob_classic.step_message_ratchet_sender().unwrap();
        let mk_other = bob_hybrid_other.step_message_ratchet_sender().unwrap();
        assert_ne!(mk_bob, mk_classic);
        assert_ne!(mk_bob, mk_other);
        assert_ne!(mk_classic, mk_other);
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
        // Bob's chains are still unset, and each restored snapshot equals the original.
        for restored in restored(&bob) {
            assert_eq!(restored, bob);
            assert_eq!(restored.header_key_sender(), None);
            assert_eq!(restored.header_key_receiver(), None);
        }

        bob.step_dh_root(&alice.public_key()).unwrap();
        for (mut alice_r, mut bob_r) in restored(&alice).into_iter().zip(restored(&bob)) {
            assert_eq!(alice_r, alice);
            assert_eq!(bob_r, bob);
            assert!(alice_r.is_paired_with(&bob_r));
            // So is which chain the next steps update, and with which keys.
            bob_r.step_dh_root(&alice_r.public_key()).unwrap();
            alice_r.step_dh_root(&bob_r.public_key()).unwrap();
            assert!(alice_r.is_paired_with(&bob_r));
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
            invalid.next_step = NextStep::UpdateSender;
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&invalid).unwrap();
            assert!(rkyv::from_bytes::<Ratchet, rkyv::rancor::Error>(&bytes).is_err());
        }
    }
}
