//! Blind index computation and compound index support.
//!
//! Blind indexes enable equality searches on encrypted data by computing
//! a deterministic keyed hash (HMAC-SHA256) of the plaintext value.
//! The hash is stored alongside the ciphertext and can be used in
//! `WHERE` clauses without revealing the original value.

use crate::crypto::hmac;
use crate::crypto::secret::SecretKey;
use crate::error::Error;

use super::normalize::normalize_for_blind_index;

/// Computes a normalized blind index for a text value.
///
/// Applies Unicode NFC normalization before hashing to ensure
/// equivalent representations produce the same index.
///
/// # Arguments
///
/// * `key` — the blind index key (must be distinct from the encryption DEK)
/// * `text` — the plaintext text value to index
/// * `context` — domain separation context (e.g., `b"users:email"`)
///
/// # Returns
///
/// 32-byte HMAC-SHA256 output.
pub fn compute_text_blind_index(
    key: &SecretKey,
    text: &str,
    context: &[u8],
) -> Result<[u8; 32], Error> {
    let normalized = normalize_for_blind_index(text);
    hmac::compute_blind_index(key, normalized.as_bytes(), context)
}

/// Computes a compound blind index from multiple field values.
///
/// The fields are concatenated with length-prefixed encoding to prevent
/// ambiguity (e.g., `["ab", "c"]` vs `["a", "bc"]` produce different indexes).
///
/// Each field is encoded as `u32_be(len) || field_bytes` before concatenation.
///
/// # Arguments
///
/// * `key` — the blind index key
/// * `fields` — the field values to combine
/// * `context` — domain separation context
///
/// # Returns
///
/// 32-byte HMAC-SHA256 output.
pub fn compute_compound_blind_index(
    key: &SecretKey,
    fields: &[&[u8]],
    context: &[u8],
) -> Result<[u8; 32], Error> {
    let mut combined = Vec::new();
    for field in fields {
        combined.extend_from_slice(&(field.len() as u32).to_be_bytes());
        combined.extend_from_slice(field);
    }
    hmac::compute_blind_index(key, &combined, context)
}

/// Truncates a blind index hash to the specified number of bytes.
///
/// Shorter indexes save storage but increase false positive rate.
/// Minimum 8 bytes (64 bits) to maintain security.
///
/// # Arguments
///
/// * `index` — the full 32-byte blind index
/// * `bytes` — the desired output length (clamped to 8..=32)
///
/// # Returns
///
/// The first `bytes` bytes of the index (clamped to [8, 32]).
pub fn truncate_blind_index(index: &[u8; 32], bytes: usize) -> Vec<u8> {
    let bytes = bytes.clamp(8, 32);
    index[..bytes].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([0xAA; 32])
    }

    #[test]
    fn text_blind_index_is_deterministic() {
        let key = test_key();
        let idx1 = compute_text_blind_index(&key, "alice@example.com", b"users:email").unwrap();
        let key2 = SecretKey::from_bytes([0xAA; 32]);
        let idx2 = compute_text_blind_index(&key2, "alice@example.com", b"users:email").unwrap();
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn text_blind_index_normalizes_unicode() {
        let key1 = SecretKey::from_bytes([0xAA; 32]);
        let key2 = SecretKey::from_bytes([0xAA; 32]);

        // NFC: e-acute as single codepoint
        let nfc = "caf\u{00E9}";
        // NFD: e + combining acute
        let nfd = "caf\u{0065}\u{0301}";

        let idx_nfc = compute_text_blind_index(&key1, nfc, b"menu:item").unwrap();
        let idx_nfd = compute_text_blind_index(&key2, nfd, b"menu:item").unwrap();
        assert_eq!(idx_nfc, idx_nfd);
    }

    #[test]
    fn text_blind_index_case_insensitive() {
        let key1 = SecretKey::from_bytes([0xAA; 32]);
        let key2 = SecretKey::from_bytes([0xAA; 32]);

        let idx_lower =
            compute_text_blind_index(&key1, "alice@example.com", b"users:email").unwrap();
        let idx_upper =
            compute_text_blind_index(&key2, "ALICE@EXAMPLE.COM", b"users:email").unwrap();
        assert_eq!(idx_lower, idx_upper);
    }

    #[test]
    fn compound_index_is_deterministic() {
        let key1 = SecretKey::from_bytes([0xBB; 32]);
        let key2 = SecretKey::from_bytes([0xBB; 32]);

        let fields: &[&[u8]] = &[b"alice", b"2024-01-01"];
        let idx1 = compute_compound_blind_index(&key1, fields, b"users:name_dob").unwrap();
        let idx2 = compute_compound_blind_index(&key2, fields, b"users:name_dob").unwrap();
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn compound_index_different_fields_different_result() {
        let key1 = SecretKey::from_bytes([0xBB; 32]);
        let key2 = SecretKey::from_bytes([0xBB; 32]);

        let fields_a: &[&[u8]] = &[b"alice", b"2024-01-01"];
        let fields_b: &[&[u8]] = &[b"bob", b"2024-01-01"];

        let idx_a = compute_compound_blind_index(&key1, fields_a, b"ctx").unwrap();
        let idx_b = compute_compound_blind_index(&key2, fields_b, b"ctx").unwrap();
        assert_ne!(idx_a, idx_b);
    }

    #[test]
    fn compound_index_field_order_matters() {
        let key1 = SecretKey::from_bytes([0xBB; 32]);
        let key2 = SecretKey::from_bytes([0xBB; 32]);

        let fields_ab: &[&[u8]] = &[b"alice", b"bob"];
        let fields_ba: &[&[u8]] = &[b"bob", b"alice"];

        let idx_ab = compute_compound_blind_index(&key1, fields_ab, b"ctx").unwrap();
        let idx_ba = compute_compound_blind_index(&key2, fields_ba, b"ctx").unwrap();
        assert_ne!(idx_ab, idx_ba);
    }

    #[test]
    fn compound_index_length_prefix_prevents_ambiguity() {
        let key1 = SecretKey::from_bytes([0xBB; 32]);
        let key2 = SecretKey::from_bytes([0xBB; 32]);

        // ["ab", "c"] vs ["a", "bc"] should differ because of length prefixing
        let fields_1: &[&[u8]] = &[b"ab", b"c"];
        let fields_2: &[&[u8]] = &[b"a", b"bc"];

        let idx1 = compute_compound_blind_index(&key1, fields_1, b"ctx").unwrap();
        let idx2 = compute_compound_blind_index(&key2, fields_2, b"ctx").unwrap();
        assert_ne!(idx1, idx2);
    }

    #[test]
    fn truncation_at_various_sizes() {
        let key = test_key();
        let full = compute_text_blind_index(&key, "test", b"ctx").unwrap();

        let t16 = truncate_blind_index(&full, 16);
        assert_eq!(t16.len(), 16);
        assert_eq!(&t16[..], &full[..16]);

        let t32 = truncate_blind_index(&full, 32);
        assert_eq!(t32.len(), 32);
        assert_eq!(&t32[..], &full[..]);

        let t8 = truncate_blind_index(&full, 8);
        assert_eq!(t8.len(), 8);
        assert_eq!(&t8[..], &full[..8]);
    }

    #[test]
    fn truncation_minimum_is_8_bytes() {
        let key = test_key();
        let full = compute_text_blind_index(&key, "test", b"ctx").unwrap();

        // Requesting fewer than 8 bytes should clamp to 8
        let t1 = truncate_blind_index(&full, 1);
        assert_eq!(t1.len(), 8);

        let t0 = truncate_blind_index(&full, 0);
        assert_eq!(t0.len(), 8);

        let t4 = truncate_blind_index(&full, 4);
        assert_eq!(t4.len(), 8);
    }

    #[test]
    fn truncation_maximum_is_32_bytes() {
        let key = test_key();
        let full = compute_text_blind_index(&key, "test", b"ctx").unwrap();

        let t64 = truncate_blind_index(&full, 64);
        assert_eq!(t64.len(), 32);

        let t100 = truncate_blind_index(&full, 100);
        assert_eq!(t100.len(), 32);
    }
}
