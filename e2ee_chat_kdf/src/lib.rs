//! Shared Argon2id KEK derivation with strict parameter bounds for the web client's ephemeral
//! `vault_kdf` Web Worker and native host tests.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Allowed Argon2id memory bounds in KiB (16 MiB ..= 256 MiB).
pub const ARGON2_MEMORY_MIN: u32 = 16 * 1024;
pub const ARGON2_MEMORY_MAX: u32 = 256 * 1024;
/// Default Argon2id memory for new vaults: 64 MiB.
pub const ARGON2_DEFAULT_MEMORY: u32 = 64 * 1024;

/// Allowed Argon2id iteration bounds.
pub const ARGON2_ITERATIONS_MIN: u32 = 1;
pub const ARGON2_ITERATIONS_MAX: u32 = 10;
pub const ARGON2_DEFAULT_ITERATIONS: u32 = 2;

/// Allowed Argon2id parallelism bounds.
pub const ARGON2_PARALLELISM_MIN: u32 = 1;
pub const ARGON2_PARALLELISM_MAX: u32 = 4;
pub const ARGON2_DEFAULT_PARALLELISM: u32 = 1;

/// Allowed Argon2id salt length bounds in bytes.
pub const ARGON2_SALT_MIN: usize = 16;
pub const ARGON2_SALT_MAX: usize = 64;

/// Output KEK length in bytes (256-bit XChaCha20-Poly1305 key).
pub const KEK_LEN: usize = 32;

/// Maximum accepted passphrase length in bytes (1 MiB) to bound memory allocation in the worker.
pub const MAX_PASSPHRASE_BYTES: usize = 1 << 20;

/// Validate Argon2id KDF parameters BEFORE allocating Argon2id memory.
pub fn validate_params(
    salt_len: usize,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), String> {
    if !(ARGON2_SALT_MIN..=ARGON2_SALT_MAX).contains(&salt_len) {
        return Err(format!("invalid vault salt length {salt_len}"));
    }
    if !(ARGON2_MEMORY_MIN..=ARGON2_MEMORY_MAX).contains(&memory_kib) {
        return Err(format!(
            "Argon2 memory {memory_kib} KiB outside allowed range [{ARGON2_MEMORY_MIN}..={ARGON2_MEMORY_MAX}]"
        ));
    }
    if !(ARGON2_ITERATIONS_MIN..=ARGON2_ITERATIONS_MAX).contains(&iterations) {
        return Err(format!(
            "Argon2 iterations {iterations} outside allowed range [{ARGON2_ITERATIONS_MIN}..={ARGON2_ITERATIONS_MAX}]"
        ));
    }
    if !(ARGON2_PARALLELISM_MIN..=ARGON2_PARALLELISM_MAX).contains(&parallelism) {
        return Err(format!(
            "Argon2 parallelism {parallelism} outside allowed range [{ARGON2_PARALLELISM_MIN}..={ARGON2_PARALLELISM_MAX}]"
        ));
    }
    Ok(())
}

/// Derive a temporary 32-byte Argon2id v0x13 KEK from `passphrase` and `salt`, enforcing strict
/// parameter bounds matching `e2ee_chat_web::vault`.
pub fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; KEK_LEN]>, String> {
    if passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err("passphrase exceeds maximum allowed length".to_string());
    }
    validate_params(salt.len(), memory_kib, iterations, parallelism)?;
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEK_LEN))
        .map_err(|e| e.to_string())?;
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, kek.as_mut_slice())
        .map_err(|e| e.to_string())?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_kek_is_deterministic_and_sensitive_to_inputs() {
        let salt_a = [0x11u8; 16];
        let salt_b = [0x22u8; 16];
        let k1 = derive_kek(b"correct horse battery", &salt_a, ARGON2_MEMORY_MIN, 1, 1)
            .expect("valid derivation");
        let k2 = derive_kek(b"correct horse battery", &salt_a, ARGON2_MEMORY_MIN, 1, 1)
            .expect("deterministic derivation");
        assert_eq!(*k1, *k2);
        assert_ne!(*k1, [0u8; KEK_LEN]);

        let k_other_pass =
            derive_kek(b"other passphrase", &salt_a, ARGON2_MEMORY_MIN, 1, 1).expect("other pass");
        assert_ne!(*k1, *k_other_pass);

        let k_other_salt = derive_kek(b"correct horse battery", &salt_b, ARGON2_MEMORY_MIN, 1, 1)
            .expect("other salt");
        assert_ne!(*k1, *k_other_salt);

        let k_other_iter = derive_kek(b"correct horse battery", &salt_a, ARGON2_MEMORY_MIN, 2, 1)
            .expect("other iterations");
        assert_ne!(*k1, *k_other_iter);
    }

    #[test]
    fn derive_kek_enforces_strict_parameter_bounds() {
        let valid_salt = [0xAAu8; 16];

        // Salt length bounds.
        assert!(derive_kek(b"pass", &[], ARGON2_MEMORY_MIN, 1, 1).is_err());
        assert!(derive_kek(b"pass", &[0u8; 15], ARGON2_MEMORY_MIN, 1, 1).is_err());
        assert!(derive_kek(b"pass", &[0u8; 65], ARGON2_MEMORY_MIN, 1, 1).is_err());
        assert!(derive_kek(b"pass", &[0u8; 64], ARGON2_MEMORY_MIN, 1, 1).is_ok());

        // Memory bounds.
        assert!(derive_kek(b"pass", &valid_salt, ARGON2_MEMORY_MIN - 1, 1, 1).is_err());
        assert!(derive_kek(b"pass", &valid_salt, ARGON2_MEMORY_MAX + 1, 1, 1).is_err());
        assert!(derive_kek(b"pass", &valid_salt, u32::MAX, 1, 1).is_err());

        // Iteration bounds.
        assert!(derive_kek(b"pass", &valid_salt, ARGON2_MEMORY_MIN, 0, 1).is_err());
        assert!(derive_kek(b"pass", &valid_salt, ARGON2_MEMORY_MIN, 11, 1).is_err());

        // Parallelism bounds.
        assert!(derive_kek(b"pass", &valid_salt, ARGON2_MEMORY_MIN, 1, 0).is_err());
        assert!(derive_kek(b"pass", &valid_salt, ARGON2_MEMORY_MIN, 1, 5).is_err());

        // Passphrase upper cap.
        let huge = vec![b'a'; MAX_PASSPHRASE_BYTES + 1];
        assert!(derive_kek(&huge, &valid_salt, ARGON2_MEMORY_MIN, 1, 1).is_err());
    }
}
