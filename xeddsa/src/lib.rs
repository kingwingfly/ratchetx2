#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    elided_lifetimes_in_paths
)]

use core::fmt;

/// Re-export curve25519_dalek.
pub use curve25519_dalek::Scalar;
use curve25519_dalek::{
    EdwardsPoint, MontgomeryPoint, constants::X25519_BASEPOINT, traits::IsIdentity,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallyNegatable};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of a public key, a Montgomery u-coordinate as curve25519-dalek encodes it. A DH
/// output is as long.
pub const PUBLIC_KEY_LENGTH: usize = X25519_BASEPOINT.as_bytes().len();
/// Length of a signature, which is an Ed25519 signature.
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;
/// Length of a private key, a scalar as curve25519-dalek encodes it.
pub const PRIVATE_KEY_LENGTH: usize = Scalar::ZERO.as_bytes().len();

/// hash1's prefix, 2^b - 2 in b bits (little-endian): 0xFE, then 0xFF bytes up to the length
/// of an encoded Ed25519 point.
const HASH1_PREFIX: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = {
    let mut prefix = [0xFF; ed25519_dalek::PUBLIC_KEY_LENGTH];
    prefix[0] = 0xFE;
    prefix
};

/// Returns `true` if `bytes` is a canonical little-endian Curve25519 Montgomery u-coordinate:
/// bit 255 is clear (`bytes[31] & 0x80 == 0`) and the integer is strictly less than 2^255 - 19.
pub fn is_canonical_public_key(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> bool {
    if bytes[31] & 0x80 != 0 {
        return false;
    }
    // 2^255 - 19 in little-endian is [0xed, 0xff, ..., 0xff, 0x7f].
    !(bytes[31] == 0x7f && bytes[1..31].iter().all(|&b| b == 0xff) && bytes[0] >= 0xed)
}

/// Validates that `bytes` is a canonical encoding of a Curve25519 point in the prime-order
/// subgroup (torsion-free and non-identity).
fn decode_prime_order_point(bytes: &[u8]) -> Result<(MontgomeryPoint, EdwardsPoint)> {
    let raw: [u8; PUBLIC_KEY_LENGTH] = bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
    if !is_canonical_public_key(&raw) {
        return Err(Error::InvalidPublicKey);
    }
    let montgomery = MontgomeryPoint(raw);
    let edwards = montgomery.to_edwards(0).ok_or(Error::InvalidPublicKey)?;
    if !edwards.is_torsion_free() || edwards.is_identity() {
        return Err(Error::InvalidPublicKey);
    }
    Ok((montgomery, edwards))
}

/// XEdDSA errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Error {
    /// The DH public key is not [`PUBLIC_KEY_LENGTH`] bytes, not canonically encoded, not on the
    /// curve, or not in the prime-order subgroup.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The private key scalar is invalid (e.g. zero).
    #[error("invalid private key")]
    InvalidPrivateKey,
    /// The signature does not verify.
    #[error("invalid signature")]
    Signature,
    /// The system random number generator failed.
    #[error("random number generator failed")]
    Rng,
}

/// A zero scalar cannot be used as an XEdDSA private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid private key scalar (zero)")]
pub struct InvalidPrivateKey;

/// Result type with [`Error`](enum@Error).
pub type Result<T> = core::result::Result<T, Error>;

/// XEdDSA private key.
///
/// With the `serde` or `rkyv` feature, it serializes as its scalar, like
/// [`to_bytes`](Self::to_bytes): keep the output secret.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "RawXEdDSAPrivateKey"))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct XEdDSAPrivateKey {
    #[cfg_attr(feature = "rkyv", rkyv(with = ScalarDef))]
    private_key: Scalar,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename = "XEdDSAPrivateKey")]
struct RawXEdDSAPrivateKey {
    private_key: Scalar,
}

#[cfg(feature = "serde")]
impl TryFrom<RawXEdDSAPrivateKey> for XEdDSAPrivateKey {
    type Error = InvalidPrivateKey;

    fn try_from(raw: RawXEdDSAPrivateKey) -> core::result::Result<Self, Self::Error> {
        Self::try_from(raw.private_key)
    }
}

/// Archives a [`Scalar`] as its canonical non-zero bytes.
#[cfg(feature = "rkyv")]
#[derive(Zeroize, ZeroizeOnDrop, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(remote = Scalar, bytecheck(verify))]
struct ScalarDef {
    #[rkyv(getter = Scalar::to_bytes)]
    bytes: [u8; PRIVATE_KEY_LENGTH],
}

#[cfg(feature = "rkyv")]
#[derive(Debug, Error)]
#[error("invalid XEdDSA private scalar (non-canonical or zero)")]
struct InvalidScalarError;

#[cfg(feature = "rkyv")]
unsafe impl<C> rkyv::bytecheck::Verify<C> for ArchivedScalarDef
where
    C: rkyv::rancor::Fallible + ?Sized,
    C::Error: rkyv::rancor::Source,
{
    fn verify(&self, _context: &mut C) -> core::result::Result<(), C::Error> {
        if XEdDSAPrivateKey::from_bytes(self.bytes).is_none() {
            rkyv::rancor::fail!(InvalidScalarError);
        }
        Ok(())
    }
}

#[cfg(feature = "rkyv")]
impl From<ScalarDef> for Scalar {
    fn from(scalar: ScalarDef) -> Self {
        Scalar::from_canonical_bytes(scalar.bytes)
            .into_option()
            .filter(|s| *s != Scalar::ZERO)
            .expect("rkyv archived scalar must be canonical and non-zero")
    }
}

impl fmt::Debug for XEdDSAPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XEdDSAPrivateKey").finish_non_exhaustive()
    }
}

impl TryFrom<Scalar> for XEdDSAPrivateKey {
    type Error = InvalidPrivateKey;

    /// Constructs a private key from a non-zero scalar.
    fn try_from(private_key: Scalar) -> core::result::Result<Self, InvalidPrivateKey> {
        if private_key == Scalar::ZERO {
            return Err(InvalidPrivateKey);
        }
        Ok(Self { private_key })
    }
}

impl XEdDSAPrivateKey {
    /// Generate a new XEdDSA private key using wide 64-byte scalar reduction.
    ///
    /// # Panics
    ///
    /// Panics if the system random number generator fails. Prefer [`try_generate`](Self::try_generate)
    /// when RNG errors must be handled without panicking.
    pub fn generate() -> Self {
        Self::try_generate().expect("the system random number generator failed")
    }

    /// Generate a new XEdDSA private key using wide 64-byte scalar reduction, returning
    /// [`Error::Rng`] if the system random number generator fails.
    pub fn try_generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 64]);
        loop {
            getrandom::fill(bytes.as_mut_slice()).map_err(|_| Error::Rng)?;
            let private_key = Scalar::from_bytes_mod_order_wide(&bytes);
            if private_key != Scalar::ZERO {
                return Ok(XEdDSAPrivateKey { private_key });
            }
        }
    }

    /// The private key's bytes, its scalar's canonical encoding, e.g. to keep it between runs:
    /// keep them secret.
    pub fn to_bytes(&self) -> Zeroizing<[u8; PRIVATE_KEY_LENGTH]> {
        Zeroizing::new(self.private_key.to_bytes())
    }

    /// The private key whose [`to_bytes`](Self::to_bytes) are `bytes`; `None` unless they are a
    /// canonical, non-zero scalar encoding.
    pub fn from_bytes(bytes: [u8; PRIVATE_KEY_LENGTH]) -> Option<Self> {
        let private_key = Scalar::from_canonical_bytes(bytes).into_option()?;
        Self::try_from(private_key).ok()
    }

    /// The XEdDSA public key for the key pair.
    pub fn compute_public_key(&self) -> XEdDSAPublicKey {
        let edwards = EdwardsPoint::mul_base(&self.private_key);
        let montgomery_public_key = edwards.to_montgomery();
        let mut edwards_y = edwards.compress().to_bytes();
        edwards_y[ed25519_dalek::PUBLIC_KEY_LENGTH - 1] &= 0x7F;
        let verifying_key = VerifyingKey::from_bytes(&edwards_y)
            .expect("EdwardsPoint::mul_base yields a valid compressed Edwards point");
        XEdDSAPublicKey {
            montgomery_public_key,
            verifying_key,
        }
    }

    /// DH, as X25519, with the key pair's private key.
    ///
    /// The key pair is long-term, so this may be called any number of times.
    pub fn diffie_hellman(
        &self,
        peer_public_key: &[u8],
    ) -> Result<Zeroizing<[u8; PUBLIC_KEY_LENGTH]>> {
        if self.private_key == Scalar::ZERO {
            return Err(Error::InvalidPrivateKey);
        }
        // The private scalar is not clamped, so a non-canonical encoding, a point on the twist,
        // the identity, or a point with a small-order component must be rejected.
        let (peer_public_key, _) = decode_prime_order_point(peer_public_key)?;
        Ok(Zeroizing::new(
            (self.private_key * peer_public_key).to_bytes(),
        ))
    }

    /// Sign, as Ed25519, with the key pair's private key.
    ///
    /// # Panics
    ///
    /// Panics if the system random number generator fails. Prefer [`try_sign`](Self::try_sign)
    /// when RNG errors must be handled without panicking.
    pub fn sign(&self, message: impl AsRef<[u8]>) -> [u8; SIGNATURE_LENGTH] {
        self.try_sign(message)
            .expect("the system random number generator failed")
    }

    /// Sign, as Ed25519, with the key pair's private key, returning [`Error::Rng`] if the system
    /// random number generator fails.
    pub fn try_sign(&self, message: impl AsRef<[u8]>) -> Result<[u8; SIGNATURE_LENGTH]> {
        let message = message.as_ref();
        // Z: 64 random bytes, per the XEdDSA spec.
        let mut random = Zeroizing::new([0u8; 64]);
        loop {
            getrandom::fill(random.as_mut_slice()).map_err(|_| Error::Rng)?;
            if let Some(sig) = self.sign_with_random(message, &random) {
                return Ok(sig);
            }
        }
    }

    /// Core XEdDSA signing using caller-provided 64-byte randomizer `Z` (returns `None` only in
    /// the negligible event that `r == 0 mod l`).
    fn sign_with_random(
        &self,
        message: &[u8],
        random: &[u8; 64],
    ) -> Option<[u8; SIGNATURE_LENGTH]> {
        let mut private_key = Zeroizing::new(self.private_key);
        let mut edwards_public_key_y = EdwardsPoint::mul_base(&private_key).compress().to_bytes();
        // The sign bit is the top bit of the last byte. The verifier takes the Edwards point
        // with sign 0, so if ours is 1, negate the key: -A = (-x, y) has the same y and sign 0.
        // Branch-free, as the sign bit is secret.
        let sign = Choice::from(edwards_public_key_y[ed25519_dalek::PUBLIC_KEY_LENGTH - 1] >> 7);
        private_key.conditional_negate(sign);
        edwards_public_key_y[ed25519_dalek::PUBLIC_KEY_LENGTH - 1] &= 0x7F;

        // r = hash1(a || M || Z), streamed directly into SHA-512 with zero heap allocations.
        let digest: Zeroizing<[u8; 64]> = Zeroizing::new(
            Sha512::new()
                .chain_update(HASH1_PREFIX)
                .chain_update(private_key.as_bytes())
                .chain_update(message)
                .chain_update(random)
                .finalize()
                .into(),
        );
        let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&digest));
        if *r == Scalar::ZERO {
            return None;
        }
        let r_ = EdwardsPoint::mul_base(&r).compress();
        let h = Scalar::from_bytes_mod_order_wide(
            &Sha512::new()
                .chain_update(r_.as_bytes())
                .chain_update(edwards_public_key_y)
                .chain_update(message)
                .finalize()
                .into(),
        );
        let s = *r + h * *private_key;
        Some(Signature::from_components(r_.to_bytes(), s.to_bytes()).to_bytes())
    }
}

/// XEdDSA public key.
///
/// Always represents a canonically encoded Curve25519 point in the prime-order subgroup, with its
/// corresponding Ed25519 [`VerifyingKey`] cached at construction time so repeated signature
/// verifications avoid repeating point decompression and torsion checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XEdDSAPublicKey {
    montgomery_public_key: MontgomeryPoint,
    verifying_key: VerifyingKey,
}

impl XEdDSAPublicKey {
    /// Create a new XEdDSA public key from bytes; fails unless they are [`PUBLIC_KEY_LENGTH`]
    /// bytes, canonically encoded, and represent a prime-order non-identity Curve25519 point.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        let (montgomery_public_key, edwards) = decode_prime_order_point(bytes)?;
        let verifying_key = VerifyingKey::from_bytes(edwards.compress().as_bytes())
            .map_err(|_| Error::InvalidPublicKey)?;
        Ok(XEdDSAPublicKey {
            montgomery_public_key,
            verifying_key,
        })
    }

    /// The public key's bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.montgomery_public_key.to_bytes()
    }

    /// Verify strictly with the Ed25519 (Edwards) public key for the key pair.
    pub fn verify(&self, message: impl AsRef<[u8]>, signature: &[u8]) -> Result<()> {
        let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
        // Use ed25519-dalek's strict Ed25519 verification against the cached prime-order key.
        self.verifying_key
            .verify_strict(message.as_ref(), &signature)
            .map_err(|_| Error::Signature)?;
        Ok(())
    }
}

impl AsRef<[u8]> for XEdDSAPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.montgomery_public_key.as_bytes()
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY};

    use super::*;

    /// Little-endian encoding of the Curve25519 prime-order subgroup order ℓ.
    const BASEPOINT_ORDER_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    /// Encoding of an Ed25519 point of order 8.
    const ORDER_8: [u8; 32] = [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ];

    /// Encoding of an Ed25519 point of order 2: (0, -1), corresponding to Montgomery u = 0.
    const ORDER_2: [u8; 32] = [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];

    #[test]
    fn diffie_hellman_known_answer() {
        let alice = XEdDSAPrivateKey::try_from(Scalar::from_bytes_mod_order([11; 32])).unwrap();
        let bob = XEdDSAPrivateKey::try_from(Scalar::from_bytes_mod_order([13; 32])).unwrap();
        let shared = alice
            .diffie_hellman(bob.compute_public_key().as_ref())
            .unwrap();
        let expected = "67d234661315d06ead7a5cf135ffaaba27ac631d757d724f25900c5d1a196344";
        let hex: String = shared.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn signs_whatever_the_edwards_sign_bit() {
        // k and -k share a public key, and their Edwards public keys have opposite sign bits.
        let key = Scalar::from_bytes_mod_order([7; 32]);
        let public_key = XEdDSAPrivateKey::try_from(key)
            .unwrap()
            .compute_public_key();
        for key in [key, -key] {
            let key = XEdDSAPrivateKey::try_from(key).unwrap();
            assert_eq!(key.compute_public_key().to_bytes(), public_key.to_bytes());
            public_key.verify("hello", &key.sign("hello")).unwrap();
        }
    }

    #[test]
    fn diffie_hellman_rejects_points_outside_the_prime_order_subgroup() {
        let bob = XEdDSAPrivateKey::generate();
        let order_8 = CompressedEdwardsY(ORDER_8).decompress().unwrap();
        assert!(order_8.is_small_order());
        let honest = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order([3; 32]);
        assert!(
            bob.diffie_hellman(honest.to_montgomery().as_bytes())
                .is_ok()
        );

        // An honest-looking key plus a small-order component (small-subgroup attack).
        let attack = (honest + order_8).to_montgomery();
        assert_eq!(
            bob.diffie_hellman(attack.as_bytes()).unwrap_err(),
            Error::InvalidPublicKey
        );
        // Small-order points themselves.
        let order_8 = order_8.to_montgomery();
        assert_eq!(
            bob.diffie_hellman(order_8.as_bytes()).unwrap_err(),
            Error::InvalidPublicKey
        );
        assert_eq!(
            bob.diffie_hellman(&[0; 32]).unwrap_err(),
            Error::InvalidPublicKey
        );
        // A point on the twist, not on the curve.
        let twist = (2..=255)
            .map(|u| {
                let mut bytes = [0; 32];
                bytes[0] = u;
                bytes
            })
            .find(|bytes| MontgomeryPoint(*bytes).to_edwards(0).is_none())
            .unwrap();
        assert_eq!(
            bob.diffie_hellman(&twist).unwrap_err(),
            Error::InvalidPublicKey
        );
    }

    #[test]
    fn zero_public_key_forgery_fails() {
        // Under cofactored Ed25519 verification, A = [0; 32] (u = 0 -> Edwards order-2 point)
        // accepts forged signatures such as (R = order-2 or identity, s = 0).
        // `XEdDSAPublicKey::new` rejects zero/small-order keys up front so they cannot even be
        // constructed as a verifying key.
        assert_eq!(
            XEdDSAPublicKey::new(&[0; 32]).unwrap_err(),
            Error::InvalidPublicKey
        );
        assert_eq!(
            XEdDSAPublicKey::new(&ORDER_2).unwrap_err(),
            Error::InvalidPublicKey
        );
    }

    #[test]
    fn non_canonical_public_keys_rejected() {
        let alice = XEdDSAPrivateKey::try_generate().unwrap();
        let bob = XEdDSAPrivateKey::try_generate().unwrap();
        let bob_pk = bob.compute_public_key();
        assert_eq!(bob_pk, XEdDSAPublicKey::new(bob_pk.as_ref()).unwrap());
        let bob_pk_copy = bob_pk;
        assert_eq!(bob_pk, bob_pk_copy);
        let sig = bob.try_sign(b"canonical check").unwrap();
        assert!(is_canonical_public_key(&bob_pk.to_bytes()));
        bob_pk.verify(b"canonical check", &sig).unwrap();

        // 1. Flip bit 255 on a valid key.
        let mut bit255 = bob_pk.to_bytes();
        bit255[31] |= 0x80;
        assert!(!is_canonical_public_key(&bit255));
        assert_eq!(
            XEdDSAPublicKey::new(&bit255).unwrap_err(),
            Error::InvalidPublicKey
        );
        assert_eq!(
            alice.diffie_hellman(&bit255).unwrap_err(),
            Error::InvalidPublicKey
        );

        // 2. u + p for valid basepoint u = 9 (9 + (2^255 - 19) = 2^255 - 10).
        let base_priv = XEdDSAPrivateKey::try_from(Scalar::ONE).unwrap();
        let base_pub = base_priv.compute_public_key();
        assert_eq!(base_pub.to_bytes()[0], 9);
        let base_sig = base_priv.sign(b"basepoint");
        base_pub.verify(b"basepoint", &base_sig).unwrap();

        let mut u_plus_p = [0xffu8; 32];
        u_plus_p[0] = 0xed + 9; // 0xf6 -> 2^255 - 10 === 9 (mod p)
        u_plus_p[31] = 0x7f;
        assert!(!is_canonical_public_key(&u_plus_p));
        assert_eq!(
            XEdDSAPublicKey::new(&u_plus_p).unwrap_err(),
            Error::InvalidPublicKey
        );
        assert_eq!(
            alice.diffie_hellman(&u_plus_p).unwrap_err(),
            Error::InvalidPublicKey
        );

        // 3. Exact boundary values around p = 2^255 - 19.
        let p_minus_1 = ORDER_2; // [0xec, 0xff, ..., 0xff, 0x7f]
        assert!(is_canonical_public_key(&p_minus_1));

        let mut p_exact = p_minus_1;
        p_exact[0] = 0xed;
        assert!(!is_canonical_public_key(&p_exact));
        assert_eq!(
            XEdDSAPublicKey::new(&p_exact).unwrap_err(),
            Error::InvalidPublicKey
        );

        let mut max_bit255_clear = [0xffu8; 32];
        max_bit255_clear[31] = 0x7f; // 2^255 - 1 = p + 18
        assert!(!is_canonical_public_key(&max_bit255_clear));
        assert_eq!(
            XEdDSAPublicKey::new(&max_bit255_clear).unwrap_err(),
            Error::InvalidPublicKey
        );
    }

    #[test]
    fn small_order_and_torsion_keys_rejected_for_verify() {
        let order_8 = CompressedEdwardsY(ORDER_8).decompress().unwrap();
        let honest = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order([5; 32]);
        let mixed = (honest + order_8).to_montgomery();
        let order_8_m = order_8.to_montgomery();
        let mut u_one = [0u8; 32];
        u_one[0] = 1;

        for bad in [[0u8; 32], u_one, order_8_m.to_bytes(), mixed.to_bytes()] {
            assert_eq!(
                XEdDSAPublicKey::new(&bad).unwrap_err(),
                Error::InvalidPublicKey
            );
        }

        // Strict verification rejects small-order R even on an honest public key.
        let bob = XEdDSAPrivateKey::generate();
        let bob_pk = bob.compute_public_key();
        let mut bad_r_sig = [0u8; SIGNATURE_LENGTH];
        bad_r_sig[..32].copy_from_slice(&ORDER_8);
        assert_eq!(
            bob_pk.verify(b"msg", &bad_r_sig).unwrap_err(),
            Error::Signature
        );
    }

    #[test]
    fn fixed_randomizer_kat_and_malleability_rejection() {
        // Test both sign-bit orientations (k and -k) with a fixed 64-byte randomizer Z.
        let k = Scalar::from_bytes_mod_order([0x2au8; 32]);
        let z = [0x5cu8; 64];
        let msg = b"xeddsa fixed-randomizer KAT";

        let priv_pos = XEdDSAPrivateKey::try_from(k).unwrap();
        let priv_neg = XEdDSAPrivateKey::try_from(-k).unwrap();
        let pub_pos = priv_pos.compute_public_key();
        let pub_neg = priv_neg.compute_public_key();
        // Both k and -k share the exact same XEdDSA public key and cached Edwards verifying key.
        assert_eq!(pub_pos, pub_neg);
        assert_eq!(pub_pos, XEdDSAPublicKey::new(pub_pos.as_ref()).unwrap());

        // Because k and -k normalize to the exact same sign-0 scalar `a`, signing with the same
        // randomizer `Z` MUST produce the exact same signature bytes.
        let sig_pos = priv_pos.sign_with_random(msg, &z).unwrap();
        let sig_neg = priv_neg.sign_with_random(msg, &z).unwrap();
        assert_eq!(sig_pos, sig_neg);
        pub_pos.verify(msg, &sig_pos).unwrap();

        // Independently recompute the XEdDSA spec equations (Signal XEdDSA §2.3) and verify exact
        // bit-for-bit match against `sig_pos`:
        let mut a = k;
        let mut a_bytes = EdwardsPoint::mul_base(&a).compress().to_bytes();
        if a_bytes[31] >> 7 == 1 {
            a = -a;
            a_bytes[31] &= 0x7F;
        }
        let mut h1 = Sha512::new();
        h1.update(HASH1_PREFIX);
        h1.update(a.as_bytes());
        h1.update(msg);
        h1.update(z);
        let r = Scalar::from_bytes_mod_order_wide(&h1.finalize().into());
        let cap_r = EdwardsPoint::mul_base(&r).compress();
        let mut h2 = Sha512::new();
        h2.update(cap_r.as_bytes());
        h2.update(a_bytes);
        h2.update(msg);
        let h = Scalar::from_bytes_mod_order_wide(&h2.finalize().into());
        let s = r + h * a;
        let mut expected = [0u8; SIGNATURE_LENGTH];
        expected[..32].copy_from_slice(cap_r.as_bytes());
        expected[32..].copy_from_slice(s.as_bytes());
        assert_eq!(sig_pos, expected);

        // Signature malleability: adding subgroup order `l` to `s` (yielding `s' = s + l >= l`)
        // MUST be rejected by strict verification.
        let mut malleated = sig_pos;
        let mut carry = 0u16;
        for (dst, &ord) in malleated[32..].iter_mut().zip(BASEPOINT_ORDER_BYTES.iter()) {
            let sum = u16::from(*dst) + u16::from(ord) + carry;
            *dst = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + l must fit in 256 bits when s < l < 2^253");
        assert_eq!(
            pub_pos.verify(msg, &malleated).unwrap_err(),
            Error::Signature
        );

        // `s == l` directly must also be rejected.
        let mut s_eq_l = sig_pos;
        s_eq_l[32..].copy_from_slice(&BASEPOINT_ORDER_BYTES);
        assert_eq!(pub_pos.verify(msg, &s_eq_l).unwrap_err(), Error::Signature);
    }

    #[test]
    fn zero_and_non_canonical_private_scalars_rejected() {
        assert!(XEdDSAPrivateKey::from_bytes([0u8; PRIVATE_KEY_LENGTH]).is_none());
        assert!(XEdDSAPrivateKey::from_bytes([0xffu8; PRIVATE_KEY_LENGTH]).is_none());
        assert!(XEdDSAPrivateKey::from_bytes(BASEPOINT_ORDER_BYTES).is_none());
        assert!(XEdDSAPrivateKey::from_bytes((-Scalar::ONE).to_bytes()).is_some());

        let valid = XEdDSAPrivateKey::generate();
        let round_trip = XEdDSAPrivateKey::from_bytes(*valid.to_bytes()).unwrap();
        assert_eq!(
            valid.compute_public_key().to_bytes(),
            round_trip.compute_public_key().to_bytes()
        );

        assert_eq!(
            XEdDSAPrivateKey::try_from(Scalar::ZERO).unwrap_err(),
            InvalidPrivateKey
        );
        assert!(XEdDSAPrivateKey::try_from(Scalar::ONE).is_ok());

        // Exercise the DH and verification checks even if an internal caller bypasses construction.
        let zero_priv = XEdDSAPrivateKey {
            private_key: Scalar::ZERO,
        };
        assert_eq!(
            zero_priv
                .diffie_hellman(valid.compute_public_key().as_ref())
                .unwrap_err(),
            Error::InvalidPrivateKey
        );
        let forged = zero_priv.sign(b"zero scalar");
        assert_eq!(
            XEdDSAPublicKey::new(zero_priv.compute_public_key().as_ref()).unwrap_err(),
            Error::InvalidPublicKey
        );
        assert_eq!(
            zero_priv
                .compute_public_key()
                .verify(b"zero scalar", &forged)
                .unwrap_err(),
            Error::Signature
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_zero_and_non_canonical_scalars() {
        let valid = XEdDSAPrivateKey::generate();
        let json = serde_json::to_string(&valid).unwrap();
        let restored: XEdDSAPrivateKey = serde_json::from_str(&json).unwrap();
        assert_eq!(
            valid.compute_public_key().to_bytes(),
            restored.compute_public_key().to_bytes()
        );

        let zero_json = format!("{{\"private_key\":{:?}}}", [0u8; 32]);
        assert!(serde_json::from_str::<XEdDSAPrivateKey>(&zero_json).is_err());

        let non_canon_json = format!("{{\"private_key\":{:?}}}", [0xffu8; 32]);
        assert!(serde_json::from_str::<XEdDSAPrivateKey>(&non_canon_json).is_err());
    }

    #[cfg(feature = "rkyv")]
    #[test]
    fn rkyv_rejects_zero_and_non_canonical_scalars() {
        let valid = XEdDSAPrivateKey::generate();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&valid).unwrap();
        let restored = rkyv::from_bytes::<XEdDSAPrivateKey, rkyv::rancor::Error>(&bytes).unwrap();
        assert_eq!(
            valid.compute_public_key().to_bytes(),
            restored.compute_public_key().to_bytes()
        );

        let zero_bytes = [0u8; PRIVATE_KEY_LENGTH];
        assert!(rkyv::from_bytes::<XEdDSAPrivateKey, rkyv::rancor::Error>(&zero_bytes).is_err());

        let non_canon_bytes = [0xffu8; PRIVATE_KEY_LENGTH];
        assert!(
            rkyv::from_bytes::<XEdDSAPrivateKey, rkyv::rancor::Error>(&non_canon_bytes).is_err()
        );
    }
}
