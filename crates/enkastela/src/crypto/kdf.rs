//! HKDF-SHA256 key derivation with domain separation.
//!
//! Derives sub-keys from a master key using HKDF (RFC 5869) with SHA-256.
//! Each derived key uses a unique `info` string for domain separation, preventing
//! key confusion across different purposes.
//!
//! # Domain separation format
//!
//! ```text
//! enkastela:{purpose}:{scope}:{version}
//! ```
//!
//! Example: `enkastela:dek:users:1`

use hkdf::Hkdf;
use sha2::Sha256;

use super::secret::SecretKey;
use crate::error::Error;

/// Salt size in bytes for HKDF.
pub const SALT_SIZE: usize = 32;

/// Generates a random 32-byte salt from the OS CSPRNG.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::fill(&mut salt);
    salt
}

/// Derives a 256-bit key from a master key using HKDF-SHA256.
///
/// # Arguments
///
/// * `master_key` — the input key material
/// * `salt` — 32-byte random salt (unique per derivation)
/// * `info` — context/purpose string for domain separation
///
/// # Returns
///
/// A new [`SecretKey`] derived from the master key.
///
/// # Errors
///
/// Returns [`Error::KeyDerivationFailed`] if HKDF fails (should not happen
/// with valid inputs, but we never unwrap in security-critical code).
pub fn derive_key(master_key: &SecretKey, salt: &[u8], info: &[u8]) -> Result<SecretKey, Error> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(SecretKey::from_bytes(okm))
}

/// Builds an HKDF info string with domain separation.
///
/// Format: `enkastela:{purpose}:{scope}:{version}`
///
/// # Arguments
///
/// * `purpose` — key purpose (e.g., "dek", "blind", "tenant", "audit")
/// * `scope` — scope identifier (e.g., table name, tenant ID)
/// * `version` — key version number
pub fn build_info(purpose: &str, scope: &str, version: u32) -> Vec<u8> {
    format!("enkastela:{purpose}:{scope}:{version}").into_bytes()
}

/// Derives a 64-byte key material for AES-256-SIV (which requires 512-bit key).
///
/// Uses HKDF-SHA256 with the info string to derive 64 bytes.
/// The returned value is wrapped in [`zeroize::Zeroizing`] to ensure key material
/// is scrubbed from memory when dropped.
pub fn derive_siv_key_material(
    master_key: &SecretKey,
    salt: &[u8],
    info: &[u8],
) -> Result<zeroize::Zeroizing<[u8; 64]>, Error> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key.as_bytes());
    let mut okm = zeroize::Zeroizing::new([0u8; 64]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master_key() -> SecretKey {
        SecretKey::from_bytes([0xAA; 32])
    }

    #[test]
    fn derive_key_deterministic() {
        let mk = master_key();
        let salt = [0x01; SALT_SIZE];
        let info = b"enkastela:dek:users:1";

        let k1 = derive_key(&mk, &salt, info).unwrap();
        let k2 = derive_key(&mk, &salt, info).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_salt_different_key() {
        let mk = master_key();
        let salt1 = [0x01; SALT_SIZE];
        let salt2 = [0x02; SALT_SIZE];
        let info = b"enkastela:dek:users:1";

        let k1 = derive_key(&mk, &salt1, info).unwrap();
        let k2 = derive_key(&mk, &salt2, info).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_info_different_key() {
        let mk = master_key();
        let salt = [0x01; SALT_SIZE];

        let k1 = derive_key(&mk, &salt, b"enkastela:dek:users:1").unwrap();
        let k2 = derive_key(&mk, &salt, b"enkastela:dek:orders:1").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_version_different_key() {
        let mk = master_key();
        let salt = [0x01; SALT_SIZE];

        let k1 = derive_key(&mk, &salt, b"enkastela:dek:users:1").unwrap();
        let k2 = derive_key(&mk, &salt, b"enkastela:dek:users:2").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn output_is_32_bytes() {
        let mk = master_key();
        let salt = generate_salt();
        let k = derive_key(&mk, &salt, b"test").unwrap();
        assert_eq!(k.as_bytes().len(), 32);
    }

    #[test]
    fn build_info_format() {
        let info = build_info("dek", "users", 3);
        assert_eq!(info, b"enkastela:dek:users:3");
    }

    #[test]
    fn derive_siv_key_material_is_64_bytes() {
        let mk = master_key();
        let salt = generate_salt();
        let km = derive_siv_key_material(&mk, &salt, b"test").unwrap();
        assert_eq!(km.len(), 64);
    }

    #[test]
    fn salt_generation_unique() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }
}
