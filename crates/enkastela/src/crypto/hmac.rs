//! HMAC-SHA256 for blind index computation.
//!
//! Computes deterministic keyed hashes of plaintext values, enabling
//! equality search on encrypted data without exposing the plaintext.
//!
//! # Security
//!
//! - The blind index key MUST be different from the encryption DEK
//! - HMAC output is deterministic: same (key, input) → same hash
//! - This leaks equality — an attacker can see when two values match

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::secret::SecretKey;
use crate::error::Error;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 output size in bytes.
pub const HMAC_OUTPUT_SIZE: usize = 32;

/// Computes HMAC-SHA256 for blind index lookup.
///
/// # Arguments
///
/// * `key` — the blind index key (derived separately from the encryption DEK)
/// * `data` — the plaintext value to index
/// * `context` — domain separation context (e.g., `"users:email"`)
///
/// # Returns
///
/// 32-byte HMAC-SHA256 output.
///
/// # Errors
///
/// Returns [`Error::EncryptionFailed`] if the HMAC key setup fails.
pub fn compute_blind_index(
    key: &SecretKey,
    data: &[u8],
    context: &[u8],
) -> Result<[u8; HMAC_OUTPUT_SIZE], Error> {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).map_err(|_| Error::EncryptionFailed)?;

    // Domain separation: hash the context first, then the data
    mac.update(context);
    mac.update(b":");
    mac.update(data);

    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut output = [0u8; HMAC_OUTPUT_SIZE];
    output.copy_from_slice(&bytes);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blind_key() -> SecretKey {
        SecretKey::from_bytes([0xBB; 32])
    }

    #[test]
    fn same_input_same_output() {
        let key = blind_key();
        let h1 = compute_blind_index(&key, b"alice@example.com", b"users:email").unwrap();
        let h2 = compute_blind_index(&key, b"alice@example.com", b"users:email").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_input_different_output() {
        let key = blind_key();
        let h1 = compute_blind_index(&key, b"alice@example.com", b"users:email").unwrap();
        let h2 = compute_blind_index(&key, b"bob@example.com", b"users:email").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_key_different_output() {
        let k1 = blind_key();
        let k2 = SecretKey::from_bytes([0xCC; 32]);
        let h1 = compute_blind_index(&k1, b"data", b"ctx").unwrap();
        let h2 = compute_blind_index(&k2, b"data", b"ctx").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_context_different_output() {
        let key = blind_key();
        let h1 = compute_blind_index(&key, b"same", b"users:email").unwrap();
        let h2 = compute_blind_index(&key, b"same", b"orders:email").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn output_is_32_bytes() {
        let key = blind_key();
        let h = compute_blind_index(&key, b"data", b"ctx").unwrap();
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn empty_data() {
        let key = blind_key();
        let h = compute_blind_index(&key, b"", b"ctx").unwrap();
        assert_eq!(h.len(), 32);
        // Should not panic on empty input
    }
}
