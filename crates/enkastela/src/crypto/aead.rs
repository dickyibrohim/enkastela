//! AES-256-GCM authenticated encryption.
//!
//! Provides randomized authenticated encryption with associated data (AEAD).
//! Each encryption generates a fresh 96-bit nonce from the OS CSPRNG.
//!
//! # Wire layout
//!
//! The output of [`encrypt`] is: `nonce(12B) || ciphertext || tag(16B)`
//!
//! # Security
//!
//! - Nonces are random, never reused (96-bit from OsRng)
//! - AAD (Additional Authenticated Data) binds ciphertext to its context
//! - Decrypted plaintext is returned in [`zeroize::Zeroizing<Vec<u8>>`]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

use super::nonce::{generate_nonce, NONCE_SIZE};
use super::secret::SecretKey;
use crate::error::Error;

/// AES-256-GCM authentication tag size in bytes.
pub const TAG_SIZE: usize = 16;

/// Minimum ciphertext size: nonce (12) + tag (16) = 28 bytes.
pub const MIN_CIPHERTEXT_SIZE: usize = NONCE_SIZE + TAG_SIZE;

/// Encrypts plaintext using AES-256-GCM with a random nonce.
///
/// # Arguments
///
/// * `key` — 256-bit encryption key
/// * `plaintext` — data to encrypt (can be empty)
/// * `aad` — additional authenticated data (e.g., `"table:column"`)
///
/// # Returns
///
/// `nonce(12B) || ciphertext || tag(16B)` as a `Vec<u8>`.
///
/// # Errors
///
/// Returns [`Error::EncryptionFailed`] if encryption fails.
pub fn encrypt(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::EncryptionFailed)?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|_| Error::EncryptionFailed)?;

    // Output: nonce || ciphertext || tag
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext_with_tag.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext_with_tag);
    Ok(output)
}

/// Decrypts ciphertext produced by [`encrypt`].
///
/// # Arguments
///
/// * `key` — 256-bit encryption key (must match the key used for encryption)
/// * `ciphertext` — output of [`encrypt`]: `nonce(12B) || ciphertext || tag(16B)`
/// * `aad` — additional authenticated data (must match what was used for encryption)
///
/// # Returns
///
/// Decrypted plaintext wrapped in [`Zeroizing`] for automatic memory cleanup.
///
/// # Errors
///
/// Returns [`Error::DecryptionFailed`] if:
/// - The ciphertext is too short
/// - The authentication tag does not verify (wrong key, tampered data, wrong AAD)
///
/// The error deliberately does not distinguish between failure modes to prevent
/// oracle attacks.
pub fn decrypt(
    key: &SecretKey,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if ciphertext.len() < MIN_CIPHERTEXT_SIZE {
        return Err(Error::DecryptionFailed);
    }

    let (nonce_bytes, ct_with_tag) = ciphertext.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::DecryptionFailed)?;

    let payload = Payload {
        msg: ct_with_tag,
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello world";
        let aad = b"users:email";

        let ct = encrypt(&key, plaintext, aad).unwrap();
        let pt = decrypt(&key, &ct, aad).unwrap();
        assert_eq!(&*pt, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = test_key();
        let ct = encrypt(&key, b"", b"test:col").unwrap();
        assert_eq!(ct.len(), MIN_CIPHERTEXT_SIZE); // nonce + tag, no ciphertext body
        let pt = decrypt(&key, &ct, b"test:col").unwrap();
        assert_eq!(&*pt, b"");
    }

    #[test]
    fn encrypt_decrypt_large_plaintext() {
        let key = test_key();
        let plaintext = vec![0xABu8; 64 * 1024]; // 64 KiB
        let ct = encrypt(&key, &plaintext, b"big:data").unwrap();
        let pt = decrypt(&key, &ct, b"big:data").unwrap();
        assert_eq!(&*pt, &plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = test_key();
        let key2 = SecretKey::from_bytes([0xFF; 32]);
        let ct = encrypt(&key1, b"secret", b"aad").unwrap();
        assert!(decrypt(&key2, &ct, b"aad").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let ct = encrypt(&key, b"secret", b"users:email").unwrap();
        assert!(decrypt(&key, &ct, b"users:phone").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let mut ct = encrypt(&key, b"secret", b"aad").unwrap();
        // Flip a bit in the ciphertext body (after nonce, before tag)
        if ct.len() > NONCE_SIZE + 1 {
            ct[NONCE_SIZE] ^= 0x01;
        }
        assert!(decrypt(&key, &ct, b"aad").is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let key = test_key();
        let mut ct = encrypt(&key, b"secret", b"aad").unwrap();
        // Flip last byte (part of the tag)
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&key, &ct, b"aad").is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let key = test_key();
        let ct = encrypt(&key, b"secret", b"aad").unwrap();
        // Too short
        assert!(decrypt(&key, &ct[..10], b"aad").is_err());
        assert!(decrypt(&key, &ct[..MIN_CIPHERTEXT_SIZE - 1], b"aad").is_err());
    }

    #[test]
    fn two_encryptions_produce_different_ciphertexts() {
        let key = test_key();
        let ct1 = encrypt(&key, b"same", b"aad").unwrap();
        let ct2 = encrypt(&key, b"same", b"aad").unwrap();
        // Different nonces → different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn ciphertext_layout() {
        let key = test_key();
        let plaintext = b"hello";
        let ct = encrypt(&key, plaintext, b"aad").unwrap();
        // Expected: 12 (nonce) + 5 (plaintext) + 16 (tag) = 33
        assert_eq!(ct.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }
}
