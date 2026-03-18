//! AES-256-SIV deterministic encryption.
//!
//! Provides deterministic authenticated encryption — the same plaintext + key + AAD
//! always produces the same ciphertext. This is useful for unique constraints and
//! exact-match lookups, but leaks equality (an attacker can see when two values match).
//!
//! # Security
//!
//! - **Trade-off**: Same plaintext → same ciphertext (leaks equality)
//! - **Nonce-misuse resistant**: SIV mode is safe even if nonces are reused
//! - Use only where deterministic output is required (unique constraints, national IDs)

use aes_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256SivAead, Nonce,
};
use zeroize::Zeroizing;

use crate::error::Error;

/// AES-256-SIV requires a 512-bit key (two 256-bit keys internally).
/// We derive this from two SecretKeys.
const SIV_KEY_SIZE: usize = 64;

/// Encrypts plaintext using AES-256-SIV (deterministic).
///
/// The same (key, plaintext, aad) always produces the same ciphertext.
///
/// # Arguments
///
/// * `key_material` — 64 bytes of key material (two concatenated 256-bit keys)
/// * `plaintext` — data to encrypt
/// * `aad` — additional authenticated data
///
/// # Returns
///
/// The SIV ciphertext (synthetic IV prepended to encrypted data).
pub fn encrypt_deterministic(
    key_material: &[u8; SIV_KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher =
        Aes256SivAead::new_from_slice(key_material).map_err(|_| Error::EncryptionFailed)?;

    // SIV mode uses an empty nonce — the IV is derived from the plaintext
    let nonce = Nonce::default();

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(&nonce, payload)
        .map_err(|_| Error::EncryptionFailed)
}

/// Decrypts ciphertext produced by [`encrypt_deterministic`].
///
/// # Arguments
///
/// * `key_material` — 64 bytes of key material (must match encryption key)
/// * `ciphertext` — output of [`encrypt_deterministic`]
/// * `aad` — additional authenticated data (must match encryption AAD)
///
/// # Returns
///
/// Decrypted plaintext wrapped in [`Zeroizing`].
pub fn decrypt_deterministic(
    key_material: &[u8; SIV_KEY_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let cipher =
        Aes256SivAead::new_from_slice(key_material).map_err(|_| Error::DecryptionFailed)?;

    let nonce = Nonce::default();

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(&nonce, payload)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_siv_key() -> [u8; SIV_KEY_SIZE] {
        let mut key = [0u8; SIV_KEY_SIZE];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(1);
        }
        key
    }

    #[test]
    fn deterministic_roundtrip() {
        let key = test_siv_key();
        let ct = encrypt_deterministic(&key, b"hello", b"users:id").unwrap();
        let pt = decrypt_deterministic(&key, &ct, b"users:id").unwrap();
        assert_eq!(&*pt, b"hello");
    }

    #[test]
    fn same_input_same_output() {
        let key = test_siv_key();
        let ct1 = encrypt_deterministic(&key, b"same", b"aad").unwrap();
        let ct2 = encrypt_deterministic(&key, b"same", b"aad").unwrap();
        assert_eq!(ct1, ct2, "SIV must be deterministic");
    }

    #[test]
    fn different_input_different_output() {
        let key = test_siv_key();
        let ct1 = encrypt_deterministic(&key, b"hello", b"aad").unwrap();
        let ct2 = encrypt_deterministic(&key, b"world", b"aad").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn different_aad_different_output() {
        let key = test_siv_key();
        let ct1 = encrypt_deterministic(&key, b"same", b"table_a:col").unwrap();
        let ct2 = encrypt_deterministic(&key, b"same", b"table_b:col").unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = test_siv_key();
        let mut key2 = test_siv_key();
        key2[0] ^= 0xFF;
        let ct = encrypt_deterministic(&key1, b"secret", b"aad").unwrap();
        assert!(decrypt_deterministic(&key2, &ct, b"aad").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_siv_key();
        let ct = encrypt_deterministic(&key, b"secret", b"correct").unwrap();
        assert!(decrypt_deterministic(&key, &ct, b"wrong").is_err());
    }

    #[test]
    fn empty_plaintext() {
        let key = test_siv_key();
        let ct = encrypt_deterministic(&key, b"", b"aad").unwrap();
        let pt = decrypt_deterministic(&key, &ct, b"aad").unwrap();
        assert_eq!(&*pt, b"");
    }
}
