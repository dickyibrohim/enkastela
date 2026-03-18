//! AES-256 Key Wrapping (RFC 3394).
//!
//! Wraps Data Encryption Keys (DEKs) for secure storage in the database.
//! The wrapped form provides both confidentiality and integrity protection.

use aes_kw::Kek;
use zeroize::Zeroizing;

use super::secret::SecretKey;
use crate::error::Error;

/// Wraps a DEK using AES-256 Key Wrap (RFC 3394).
///
/// # Arguments
///
/// * `wrapping_key` — the Key Encryption Key (KEK), typically the master key
/// * `dek` — the Data Encryption Key to wrap
///
/// # Returns
///
/// The wrapped key bytes (40 bytes for a 32-byte DEK: 32 + 8 byte integrity check).
pub fn wrap_key(wrapping_key: &SecretKey, dek: &SecretKey) -> Result<Vec<u8>, Error> {
    let kek = Kek::from(*wrapping_key.as_bytes());
    let mut wrapped = vec![0u8; dek.as_bytes().len() + 8]; // AES-KW adds 8 bytes
    kek.wrap(dek.as_bytes(), &mut wrapped)
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(wrapped)
}

/// Unwraps a DEK that was wrapped with [`wrap_key`].
///
/// # Arguments
///
/// * `wrapping_key` — the Key Encryption Key (must match the one used to wrap)
/// * `wrapped_key` — the wrapped key bytes
///
/// # Returns
///
/// The unwrapped [`SecretKey`].
///
/// # Errors
///
/// Returns [`Error::KeyUnwrapFailed`] if integrity verification fails
/// (wrong wrapping key or tampered wrapped key).
pub fn unwrap_key(wrapping_key: &SecretKey, wrapped_key: &[u8]) -> Result<SecretKey, Error> {
    let kek = Kek::from(*wrapping_key.as_bytes());
    let mut unwrapped = Zeroizing::new(vec![0u8; wrapped_key.len().saturating_sub(8)]);
    kek.unwrap(wrapped_key, &mut unwrapped)
        .map_err(|_| Error::KeyUnwrapFailed)?;
    SecretKey::from_slice(&unwrapped).ok_or(Error::KeyUnwrapFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapping_key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    fn dek() -> SecretKey {
        SecretKey::from_bytes([0x07; 32])
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let wk = wrapping_key();
        let original = dek();

        let wrapped = wrap_key(&wk, &original).unwrap();
        assert_eq!(wrapped.len(), 40); // 32 + 8

        let recovered = unwrap_key(&wk, &wrapped).unwrap();
        assert_eq!(recovered.as_bytes(), original.as_bytes());
    }

    #[test]
    fn wrong_wrapping_key_fails() {
        let wk1 = wrapping_key();
        let wk2 = SecretKey::from_bytes([0xFF; 32]);

        let wrapped = wrap_key(&wk1, &dek()).unwrap();
        assert!(unwrap_key(&wk2, &wrapped).is_err());
    }

    #[test]
    fn tampered_wrapped_key_fails() {
        let wk = wrapping_key();
        let mut wrapped = wrap_key(&wk, &dek()).unwrap();
        wrapped[0] ^= 0x01;
        assert!(unwrap_key(&wk, &wrapped).is_err());
    }

    #[test]
    fn truncated_wrapped_key_fails() {
        let wk = wrapping_key();
        let wrapped = wrap_key(&wk, &dek()).unwrap();
        assert!(unwrap_key(&wk, &wrapped[..20]).is_err());
    }

    #[test]
    fn empty_wrapped_key_fails() {
        let wk = wrapping_key();
        assert!(unwrap_key(&wk, &[]).is_err());
    }
}
