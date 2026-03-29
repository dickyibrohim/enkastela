//! Streaming authenticated encryption for large payloads.
//!
//! Uses a chunked approach where each chunk is independently encrypted
//! with AES-256-GCM, using a nonce derived from the base nonce and chunk
//! index. The final chunk includes a finalization marker to prevent
//! truncation attacks.
//!
//! # Wire Format
//!
//! Each chunk: `nonce(12B) || ciphertext(variable) || tag(16B)`
//! Chunks are concatenated. The last chunk's AAD includes a finalization flag.
//!
//! # Feature
//!
//! This module requires the `streaming` feature flag.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;
use crate::error::Error;

/// Default chunk size: 64 KiB.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Encrypts data in chunks using AES-256-GCM.
///
/// Each chunk is encrypted with a unique nonce derived from a random base
/// nonce and the chunk index. This allows streaming large payloads without
/// holding the entire plaintext in memory.
///
/// # Arguments
///
/// * `key` — 256-bit encryption key
/// * `plaintext` — data to encrypt (can be arbitrarily large)
/// * `aad` — additional authenticated data bound to all chunks
/// * `chunk_size` — size of each plaintext chunk in bytes
///
/// # Returns
///
/// Concatenated encrypted chunks. Format per chunk:
/// `nonce(12B) || ciphertext(variable) || tag(16B)`
pub fn encrypt_stream(
    key: &SecretKey,
    plaintext: &[u8],
    aad: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::EncryptionFailed)?;

    let chunk_size = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };

    // Generate a random base nonce
    let mut base_nonce = [0u8; 8];
    rand::fill(&mut base_nonce);

    let total_chunks = if plaintext.is_empty() {
        1
    } else {
        plaintext.len().div_ceil(chunk_size)
    };

    if total_chunks > u32::MAX as usize {
        return Err(Error::PayloadTooLarge {
            max_bytes: u32::MAX as usize * chunk_size,
        });
    }

    let mut output = Vec::new();

    // Write header: chunk count (4 bytes BE) + base nonce (8 bytes)
    output.extend_from_slice(&(total_chunks as u32).to_be_bytes());
    output.extend_from_slice(&base_nonce);

    for (i, chunk) in plaintext
        .chunks(chunk_size)
        .chain(
            // Handle empty plaintext — produce one empty chunk
            if plaintext.is_empty() {
                Some(&[][..])
            } else {
                None
            }
            .into_iter(),
        )
        .enumerate()
    {
        let is_last = i == total_chunks.saturating_sub(1) || (plaintext.is_empty() && i == 0);

        // Derive chunk nonce from base nonce + chunk index
        let chunk_nonce = derive_chunk_nonce(&base_nonce, i as u32);
        let nonce = Nonce::from_slice(&chunk_nonce);

        // Build chunk AAD: original AAD + chunk index + finalization flag
        let mut chunk_aad = aad.to_vec();
        chunk_aad.extend_from_slice(&(i as u32).to_be_bytes());
        chunk_aad.push(if is_last { 1 } else { 0 });

        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: chunk,
                    aad: &chunk_aad,
                },
            )
            .map_err(|_| Error::EncryptionFailed)?;

        // Write: nonce(12) || ciphertext+tag
        output.extend_from_slice(&chunk_nonce);
        output.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        output.extend_from_slice(&ciphertext);
    }

    Ok(output)
}

/// Decrypts a stream-encrypted payload.
///
/// # Arguments
///
/// * `key` — 256-bit encryption key (must match what was used for encryption)
/// * `ciphertext` — the concatenated encrypted chunks from [`encrypt_stream`]
/// * `aad` — additional authenticated data (must match what was used for encryption)
///
/// # Returns
///
/// Decrypted plaintext wrapped in [`Zeroizing`].
pub fn decrypt_stream(
    key: &SecretKey,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| Error::DecryptionFailed)?;

    if ciphertext.len() < 12 {
        return Err(Error::DecryptionFailed);
    }

    // Read header
    let total_chunks = u32::from_be_bytes(
        ciphertext[..4]
            .try_into()
            .map_err(|_| Error::DecryptionFailed)?,
    ) as usize;
    let base_nonce: [u8; 8] = ciphertext[4..12]
        .try_into()
        .map_err(|_| Error::DecryptionFailed)?;

    let mut offset = 12;
    let mut plaintext = Zeroizing::new(Vec::new());

    for i in 0..total_chunks {
        let is_last = i == total_chunks - 1;

        // Read chunk nonce (12 bytes)
        if offset + 12 > ciphertext.len() {
            return Err(Error::DecryptionFailed);
        }
        let chunk_nonce: [u8; 12] = ciphertext[offset..offset + 12]
            .try_into()
            .map_err(|_| Error::DecryptionFailed)?;
        offset += 12;

        // Read chunk ciphertext length (4 bytes)
        if offset + 4 > ciphertext.len() {
            return Err(Error::DecryptionFailed);
        }
        let ct_len = u32::from_be_bytes(
            ciphertext[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::DecryptionFailed)?,
        ) as usize;
        offset += 4;

        // Read chunk ciphertext
        if offset + ct_len > ciphertext.len() {
            return Err(Error::DecryptionFailed);
        }
        let chunk_ct = &ciphertext[offset..offset + ct_len];
        offset += ct_len;

        // Verify nonce matches expected derivation
        let expected_nonce = derive_chunk_nonce(&base_nonce, i as u32);
        if chunk_nonce != expected_nonce {
            return Err(Error::DecryptionFailed);
        }

        // Build chunk AAD
        let mut chunk_aad = aad.to_vec();
        chunk_aad.extend_from_slice(&(i as u32).to_be_bytes());
        chunk_aad.push(if is_last { 1 } else { 0 });

        let nonce = Nonce::from_slice(&chunk_nonce);
        let chunk_pt = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: chunk_ct,
                    aad: &chunk_aad,
                },
            )
            .map_err(|_| Error::DecryptionFailed)?;

        plaintext.extend_from_slice(&chunk_pt);
    }

    Ok(plaintext)
}

/// Derives a unique 12-byte nonce from a base nonce and chunk index.
fn derive_chunk_nonce(base: &[u8; 8], chunk_index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(base);
    nonce[8..12].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    #[test]
    fn stream_roundtrip_small() {
        let key = test_key();
        let plaintext = b"hello streaming encryption";
        let aad = b"test:column";

        let ct = encrypt_stream(&key, plaintext, aad, 16).unwrap();
        let pt = decrypt_stream(&key, &ct, aad).unwrap();
        assert_eq!(&*pt, plaintext);
    }

    #[test]
    fn stream_roundtrip_large() {
        let key = test_key();
        let plaintext = vec![0xABu8; 256 * 1024]; // 256 KiB
        let aad = b"large:payload";

        let ct = encrypt_stream(&key, &plaintext, aad, DEFAULT_CHUNK_SIZE).unwrap();
        let pt = decrypt_stream(&key, &ct, aad).unwrap();
        assert_eq!(&*pt, &plaintext);
    }

    #[test]
    fn stream_roundtrip_empty() {
        let key = test_key();
        let ct = encrypt_stream(&key, b"", b"aad", DEFAULT_CHUNK_SIZE).unwrap();
        let pt = decrypt_stream(&key, &ct, b"aad").unwrap();
        assert_eq!(&*pt, b"");
    }

    #[test]
    fn stream_wrong_aad_fails() {
        let key = test_key();
        let ct = encrypt_stream(&key, b"secret", b"correct-aad", 16).unwrap();
        let result = decrypt_stream(&key, &ct, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn stream_wrong_key_fails() {
        let key1 = test_key();
        let key2 = SecretKey::from_bytes([0x99; 32]);
        let ct = encrypt_stream(&key1, b"secret", b"aad", 16).unwrap();
        let result = decrypt_stream(&key2, &ct, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn stream_truncated_fails() {
        let key = test_key();
        let ct = encrypt_stream(&key, b"hello world test data", b"aad", 8).unwrap();
        // Truncate — remove last chunk
        let truncated = &ct[..ct.len() / 2];
        let result = decrypt_stream(&key, truncated, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn stream_exact_chunk_boundary() {
        let key = test_key();
        let plaintext = vec![0xCDu8; 64]; // exactly one chunk at size 64
        let ct = encrypt_stream(&key, &plaintext, b"aad", 64).unwrap();
        let pt = decrypt_stream(&key, &ct, b"aad").unwrap();
        assert_eq!(&*pt, &plaintext);
    }

    #[test]
    fn stream_multiple_chunks() {
        let key = test_key();
        let plaintext = vec![0xEFu8; 100]; // will split into chunks of 30
        let ct = encrypt_stream(&key, &plaintext, b"aad", 30).unwrap();
        let pt = decrypt_stream(&key, &ct, b"aad").unwrap();
        assert_eq!(&*pt, &plaintext);
    }
}
