//! Internal ML-KEM provider wrapping `ml-kem` behind optional suite features.

use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use zeroize::{Zeroize, Zeroizing};

use crate::{ErrorKind, PQ_SEED_LENGTH, PQ_SHARED_SECRET_LENGTH, PqSuite, Result};

/// Generates a fresh 64-byte FIPS 203 `(d, z)` seed and derives its encapsulation key bytes.
pub(crate) fn generate_keypair(
    suite: PqSuite,
) -> Result<(Vec<u8>, Zeroizing<[u8; PQ_SEED_LENGTH]>)> {
    if !suite.is_supported() {
        return Err(ErrorKind::UnsupportedSuite.into());
    }
    let mut seed = Zeroizing::new([0u8; PQ_SEED_LENGTH]);
    getrandom::fill(seed.as_mut_slice()).expect("the system random number generator failed");
    let ek = derive_ek(suite, &seed)?;
    Ok((ek, seed))
}

/// Deterministically derives the encapsulation key bytes from a 64-byte FIPS 203 `(d, z)` seed.
pub(crate) fn derive_ek(suite: PqSuite, seed: &[u8; PQ_SEED_LENGTH]) -> Result<Vec<u8>> {
    let seed_arr = Zeroizing::new(ml_kem::Seed::from(*seed));
    match suite {
        #[cfg(feature = "ml-kem-1024")]
        PqSuite::MlKem1024 => {
            let dk = ml_kem::DecapsulationKey1024::from_seed(*seed_arr);
            Ok(dk.encapsulation_key().to_bytes().to_vec())
        }
        #[cfg(feature = "ml-kem-768")]
        PqSuite::MlKem768 => {
            let dk = ml_kem::DecapsulationKey768::from_seed(*seed_arr);
            Ok(dk.encapsulation_key().to_bytes().to_vec())
        }
        #[allow(unreachable_patterns)]
        _ => Err(ErrorKind::UnsupportedSuite.into()),
    }
}

/// Validates `ek_bytes` per FIPS 203 and encapsulates a fresh 32-byte shared secret.
pub(crate) fn encapsulate(
    suite: PqSuite,
    ek_bytes: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; PQ_SHARED_SECRET_LENGTH]>)> {
    if !suite.is_supported() {
        return Err(ErrorKind::UnsupportedSuite.into());
    }
    let mut m = Zeroizing::new([0u8; 32]);
    getrandom::fill(m.as_mut_slice()).expect("the system random number generator failed");
    encapsulate_deterministic(suite, ek_bytes, &m)
}

/// Deterministic encapsulation for FIPS 203 KATs and internal use (caller MUST provide
/// uniformly random `m` in production).
pub(crate) fn encapsulate_deterministic(
    suite: PqSuite,
    ek_bytes: &[u8],
    m: &[u8; 32],
) -> Result<(Vec<u8>, Zeroizing<[u8; PQ_SHARED_SECRET_LENGTH]>)> {
    let m_arr = Zeroizing::new(ml_kem::B32::from(*m));
    match suite {
        #[cfg(feature = "ml-kem-1024")]
        PqSuite::MlKem1024 => {
            let ek = ml_kem::EncapsulationKey1024::new_from_slice(ek_bytes)
                .map_err(|_| ErrorKind::InvalidPublicKey)?;
            let (ct, mut ss) = ek.encapsulate_deterministic(&m_arr);
            let mut out = Zeroizing::new([0u8; PQ_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok((ct.to_vec(), out))
        }
        #[cfg(feature = "ml-kem-768")]
        PqSuite::MlKem768 => {
            let ek = ml_kem::EncapsulationKey768::new_from_slice(ek_bytes)
                .map_err(|_| ErrorKind::InvalidPublicKey)?;
            let (ct, mut ss) = ek.encapsulate_deterministic(&m_arr);
            let mut out = Zeroizing::new([0u8; PQ_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok((ct.to_vec(), out))
        }
        #[allow(unreachable_patterns)]
        _ => Err(ErrorKind::UnsupportedSuite.into()),
    }
}

/// Decapsulates `ct_bytes` using the 64-byte FIPS 203 `(d, z)` seed.
pub(crate) fn decapsulate(
    suite: PqSuite,
    seed: &[u8; PQ_SEED_LENGTH],
    ct_bytes: &[u8],
) -> Result<Zeroizing<[u8; PQ_SHARED_SECRET_LENGTH]>> {
    if !suite.is_supported() {
        return Err(ErrorKind::UnsupportedSuite.into());
    }
    if ct_bytes.len() != suite.ct_len() {
        return Err(ErrorKind::InvalidCiphertext.into());
    }
    let seed_arr = Zeroizing::new(ml_kem::Seed::from(*seed));
    match suite {
        #[cfg(feature = "ml-kem-1024")]
        PqSuite::MlKem1024 => {
            let dk = ml_kem::DecapsulationKey1024::from_seed(*seed_arr);
            let mut ss = dk
                .decapsulate_slice(ct_bytes)
                .map_err(|_| ErrorKind::InvalidCiphertext)?;
            let mut out = Zeroizing::new([0u8; PQ_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok(out)
        }
        #[cfg(feature = "ml-kem-768")]
        PqSuite::MlKem768 => {
            let dk = ml_kem::DecapsulationKey768::from_seed(*seed_arr);
            let mut ss = dk
                .decapsulate_slice(ct_bytes)
                .map_err(|_| ErrorKind::InvalidCiphertext)?;
            let mut out = Zeroizing::new([0u8; PQ_SHARED_SECRET_LENGTH]);
            out.copy_from_slice(ss.as_slice());
            ss.zeroize();
            Ok(out)
        }
        #[allow(unreachable_patterns)]
        _ => Err(ErrorKind::UnsupportedSuite.into()),
    }
}
