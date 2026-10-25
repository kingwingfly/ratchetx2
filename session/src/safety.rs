//! Safety numbers, as Signal computes them (its numeric fingerprint, version 1).
//!
//! Each side's half comes from its own identity key alone, made slow to compute, so a
//! man-in-the-middle must find a key whose half matches each real key's, rather than any pair of
//! keys whose numbers happen to match.

use sha2::{Digest, Sha512};
use x3dh::PublicKey;

/// Rounds of SHA-512 per half, as Signal's.
const ITERATIONS: usize = 5200;
/// The fingerprint version, Signal's first.
const VERSION: [u8; 2] = [0, 0];
/// The type byte Signal puts before a Curve25519 public key.
const DJB_TYPE: u8 = 0x05;
/// What stands in for Signal's stable identifier, its phone number or account ID: here the identity
/// key is the account, so it only sets these numbers apart from other apps'.
const STABLE_ID: &[u8] = b"e2ee-chat";

/// The safety number of the session between `me` and `peer`: 60 digits, the same on both sides
/// only if each has the other's real identity key. Compare it out of band, e.g. in person.
pub fn safety_number(me: &PublicKey, peer: &PublicKey) -> String {
    join(half(me, STABLE_ID), half(peer, STABLE_ID))
}

/// Both halves, the smaller first, so that both sides show the same.
fn join(mine: String, theirs: String) -> String {
    if mine < theirs {
        mine + &theirs
    } else {
        theirs + &mine
    }
}

/// The 30 digits of `key`, owned by `stable_id`: six groups of five, each from five bytes of its
/// iterated hash.
fn half(key: &PublicKey, stable_id: &[u8]) -> String {
    let mut serialized = [DJB_TYPE; 1 + size_of::<PublicKey>()];
    serialized[1..].copy_from_slice(key);
    let mut hash = Sha512::new()
        .chain_update(VERSION)
        .chain_update(serialized)
        .chain_update(stable_id)
        .chain_update(serialized)
        .finalize();
    for _ in 1..ITERATIONS {
        hash = Sha512::new()
            .chain_update(hash)
            .chain_update(serialized)
            .finalize();
    }
    hash.as_chunks::<5>()
        .0
        .iter()
        .take(6)
        .map(|chunk| {
            let number = chunk.iter().fold(0u64, |n, byte| n << 8 | u64::from(*byte));
            format!("{:05}", number % 100_000)
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    /// Signal's test vector, from libsignal's `fingerprint.rs`.
    #[test]
    fn matches_signal() {
        let alice: PublicKey = *b"\x06\x86\x3b\xc6\x6d\x02\xb4\x0d\x27\xb8\xd4\x9c\xa7\xc0\x9e\x92\
            \x39\x23\x6f\x9d\x7d\x25\xd6\xfc\xca\x5c\xe1\x3c\x70\x64\xd8\x68";
        let bob: PublicKey = *b"\xf7\x81\xb6\xfb\x32\xfe\xd9\xba\x1c\xf2\xde\x97\x8d\x4d\x5d\xa2\
            \x8d\xc3\x40\x46\xae\x81\x44\x02\xb5\xc0\xdb\xd9\x6f\xda\x90\x7b";
        assert_eq!(
            join(half(&alice, b"+14152222222"), half(&bob, b"+14153333333")),
            "300354477692869396892869876765458257569162576843440918079131"
        );
    }

    #[test]
    fn both_sides_show_the_same() {
        let (alice, bob) = ([1; 32], [2; 32]);
        assert_eq!(safety_number(&alice, &bob), safety_number(&bob, &alice));
        assert_eq!(safety_number(&alice, &bob).len(), 60);
        assert_ne!(safety_number(&alice, &bob), safety_number(&alice, &[3; 32]));
    }
}
