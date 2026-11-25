//! Internal ML-KEM provider wrapping `ml-kem` behind optional suite features.

use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use zeroize::{Zeroize, Zeroizing};

use crate::{ErrorKind, PQ_SEED_LENGTH, PQ_SHARED_SECRET_LENGTH, PqSuite, Result};

/// Dispatches an operation over the enabled [`PqSuite`] parameter sets without duplicating
/// `MlKem1024`/`MlKem768` arms.
macro_rules! dispatch_suite {
    ($suite:expr, |$k:ident| $body:expr) => {
        match $suite {
            #[cfg(feature = "ml-kem-1024")]
            PqSuite::MlKem1024 => {
                type $k = ml_kem::MlKem1024;
                $body
            }
            #[cfg(feature = "ml-kem-768")]
            PqSuite::MlKem768 => {
                type $k = ml_kem::MlKem768;
                $body
            }
            #[allow(unreachable_patterns)]
            _ => Err(ErrorKind::UnsupportedSuite.into()),
        }
    };
}

/// Generates a fresh 64-byte FIPS 203 `(d, z)` seed and derives its encapsulation key bytes.
pub(crate) fn generate_keypair(
    suite: PqSuite,
) -> Result<(Vec<u8>, Zeroizing<[u8; PQ_SEED_LENGTH]>)> {
    if !suite.is_supported() {
        return Err(ErrorKind::UnsupportedSuite.into());
    }
    let mut seed = Zeroizing::new([0u8; PQ_SEED_LENGTH]);
    getrandom::fill(seed.as_mut_slice()).map_err(|_| ErrorKind::Rng)?;
    let ek = derive_ek(suite, &seed)?;
    Ok((ek, seed))
}

/// Deterministically derives the encapsulation key bytes from a 64-byte FIPS 203 `(d, z)` seed.
pub(crate) fn derive_ek(suite: PqSuite, seed: &[u8; PQ_SEED_LENGTH]) -> Result<Vec<u8>> {
    let seed_arr = Zeroizing::new(ml_kem::Seed::from(*seed));
    dispatch_suite!(suite, |K| {
        let dk = ml_kem::DecapsulationKey::<K>::from_seed(*seed_arr);
        Ok(dk.encapsulation_key().to_bytes().as_slice().to_vec())
    })
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
    getrandom::fill(m.as_mut_slice()).map_err(|_| ErrorKind::Rng)?;
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
    dispatch_suite!(suite, |K| {
        let ek = ml_kem::EncapsulationKey::<K>::new_from_slice(ek_bytes)
            .map_err(|_| ErrorKind::InvalidPublicKey)?;
        let (ct, mut ss) = ek.encapsulate_deterministic(&m_arr);
        let mut out = Zeroizing::new([0u8; PQ_SHARED_SECRET_LENGTH]);
        out.copy_from_slice(ss.as_slice());
        ss.zeroize();
        Ok((ct.as_slice().to_vec(), out))
    })
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
    dispatch_suite!(suite, |K| {
        let dk = ml_kem::DecapsulationKey::<K>::from_seed(*seed_arr);
        let mut ss = dk
            .decapsulate_slice(ct_bytes)
            .map_err(|_| ErrorKind::InvalidCiphertext)?;
        let mut out = Zeroizing::new([0u8; PQ_SHARED_SECRET_LENGTH]);
        out.copy_from_slice(ss.as_slice());
        ss.zeroize();
        Ok(out)
    })
}
