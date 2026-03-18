//! Bloom filter blind indexes for partial/substring search.
//!
//! Generates n-grams from input text, HMACs each n-gram, and sets bits in a
//! Bloom filter. This enables encrypted partial-match queries like
//! "find all emails containing 'example.com'" without decrypting.
//!
//! # How It Works
//!
//! 1. Input text is normalized (NFC, lowercase, trim)
//! 2. N-grams of configurable size are extracted
//! 3. Each n-gram is HMAC'd with a secret key
//! 4. HMAC output sets `k` bits in a Bloom filter of `m` bits
//! 5. The resulting bit vector is stored alongside the ciphertext
//!
//! # Query
//!
//! To search, compute the Bloom filter for the search term and check if all
//! set bits are also set in the stored filter (subset check).
//!
//! # Security
//!
//! - Bloom filters leak n-gram frequency distribution
//! - False positives are possible (tunable via filter size)
//! - Opt-in only: users must explicitly enable this

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::secret::SecretKey;

/// Configuration for Bloom filter generation.
#[derive(Debug, Clone)]
pub struct BloomConfig {
    /// Size of the filter in bits.
    pub filter_bits: usize,
    /// Number of hash functions (bits set per n-gram).
    pub num_hashes: u32,
    /// N-gram size in characters.
    pub ngram_size: usize,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            filter_bits: 256,
            num_hashes: 3,
            ngram_size: 3,
        }
    }
}

/// A Bloom filter for encrypted partial-match search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    /// Bit vector stored as bytes (little-endian bit ordering within each byte).
    pub bits: Vec<u8>,
    /// Number of valid bits.
    pub num_bits: usize,
}

impl BloomFilter {
    /// Creates an empty Bloom filter with the given number of bits.
    pub fn new(num_bits: usize) -> Self {
        let num_bytes = num_bits.div_ceil(8);
        Self {
            bits: vec![0u8; num_bytes],
            num_bits,
        }
    }

    /// Sets a bit at the given position.
    fn set_bit(&mut self, pos: usize) {
        let pos = pos % self.num_bits;
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        self.bits[byte_idx] |= 1 << bit_idx;
    }

    /// Checks if a bit is set at the given position.
    pub fn get_bit(&self, pos: usize) -> bool {
        let pos = pos % self.num_bits;
        let byte_idx = pos / 8;
        let bit_idx = pos % 8;
        (self.bits[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Returns whether `other` is a subset of this filter.
    ///
    /// If `other.contains(self)` is true, then any n-gram in `other` is
    /// *probably* also in `self` (subject to false positive rate).
    pub fn contains(&self, other: &BloomFilter) -> bool {
        if self.num_bits != other.num_bits {
            return false;
        }
        for (a, b) in self.bits.iter().zip(other.bits.iter()) {
            // Every bit set in `other` must also be set in `self`
            if b & !a != 0 {
                return false;
            }
        }
        true
    }

    /// Returns the number of bits set in the filter.
    pub fn popcount(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Serializes the filter to bytes: `num_bits(4B BE) || bit_data`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.bits.len());
        out.extend_from_slice(&(self.num_bits as u32).to_be_bytes());
        out.extend_from_slice(&self.bits);
        out
    }

    /// Deserializes a filter from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let num_bits = u32::from_be_bytes(data[..4].try_into().ok()?) as usize;
        let expected_bytes = num_bits.div_ceil(8);
        if data.len() != 4 + expected_bytes {
            return None;
        }
        Some(Self {
            bits: data[4..].to_vec(),
            num_bits,
        })
    }
}

/// Computes a Bloom filter for the given text.
///
/// The text is normalized (NFC, lowercase, trim), split into n-grams, and
/// each n-gram is HMAC'd to set bits in the filter.
///
/// # Arguments
///
/// * `key` — secret key for HMAC (should be derived specifically for Bloom use)
/// * `text` — input text to index
/// * `config` — Bloom filter configuration
pub fn compute_bloom_filter(key: &SecretKey, text: &str, config: &BloomConfig) -> BloomFilter {
    let normalized = crate::blind::normalize::normalize_for_blind_index(text);
    let ngrams = extract_ngrams(&normalized, config.ngram_size);

    let mut filter = BloomFilter::new(config.filter_bits);

    for ngram in &ngrams {
        let positions = hash_ngram(key, ngram, config.num_hashes, config.filter_bits);
        for pos in positions {
            filter.set_bit(pos);
        }
    }

    filter
}

/// Computes a Bloom filter for a search query.
///
/// Same as [`compute_bloom_filter`] but for the search term. To check if a
/// document matches, use `document_filter.contains(&query_filter)`.
pub fn compute_query_filter(key: &SecretKey, query: &str, config: &BloomConfig) -> BloomFilter {
    compute_bloom_filter(key, query, config)
}

/// Checks if a document's Bloom filter probably contains the query.
///
/// Returns `true` if all bits in the query filter are also set in the
/// document filter (possible match, subject to false positives).
pub fn bloom_search(document: &BloomFilter, query: &BloomFilter) -> bool {
    document.contains(query)
}

/// Extracts character n-grams from text.
fn extract_ngrams(text: &str, n: usize) -> Vec<String> {
    if n == 0 || text.is_empty() {
        return vec![];
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < n {
        return vec![text.to_string()];
    }
    chars.windows(n).map(|w| w.iter().collect()).collect()
}

/// Hashes an n-gram to `k` bit positions using double-hashing.
fn hash_ngram(key: &SecretKey, ngram: &str, k: u32, m: usize) -> Vec<usize> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(b"bloom:ngram:");
    mac.update(ngram.as_bytes());
    let tag = mac.finalize().into_bytes();

    // Use double hashing: h(i) = h1 + i * h2
    let h1 = u32::from_be_bytes([tag[0], tag[1], tag[2], tag[3]]) as usize;
    let h2 = u32::from_be_bytes([tag[4], tag[5], tag[6], tag[7]]) as usize;

    (0..k as usize)
        .map(|i| (h1.wrapping_add(i.wrapping_mul(h2))) % m)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    #[test]
    fn bloom_exact_match() {
        let key = test_key();
        let config = BloomConfig::default();
        let doc = compute_bloom_filter(&key, "alice@example.com", &config);
        let query = compute_query_filter(&key, "alice@example.com", &config);
        assert!(bloom_search(&doc, &query));
    }

    #[test]
    fn bloom_substring_match() {
        let key = test_key();
        let config = BloomConfig::default();
        let doc = compute_bloom_filter(&key, "alice@example.com", &config);
        let query = compute_query_filter(&key, "example.com", &config);
        assert!(bloom_search(&doc, &query));
    }

    #[test]
    fn bloom_substring_match_prefix() {
        let key = test_key();
        let config = BloomConfig::default();
        let doc = compute_bloom_filter(&key, "alice@example.com", &config);
        let query = compute_query_filter(&key, "alice", &config);
        assert!(bloom_search(&doc, &query));
    }

    #[test]
    fn bloom_no_match() {
        let key = test_key();
        let config = BloomConfig {
            filter_bits: 1024, // Larger filter = fewer false positives
            num_hashes: 5,
            ngram_size: 3,
        };
        let doc = compute_bloom_filter(&key, "alice@example.com", &config);
        let query = compute_query_filter(&key, "zzzznotfound", &config);
        // Should not match (very low false positive rate with 1024 bits)
        assert!(!bloom_search(&doc, &query));
    }

    #[test]
    fn bloom_case_insensitive() {
        let key = test_key();
        let config = BloomConfig::default();
        let doc = compute_bloom_filter(&key, "Alice@Example.COM", &config);
        let query = compute_query_filter(&key, "alice@example.com", &config);
        assert!(bloom_search(&doc, &query));
    }

    #[test]
    fn bloom_empty_text() {
        let key = test_key();
        let config = BloomConfig::default();
        let doc = compute_bloom_filter(&key, "", &config);
        assert_eq!(doc.popcount(), 0);
    }

    #[test]
    fn bloom_serialization_roundtrip() {
        let key = test_key();
        let config = BloomConfig::default();
        let filter = compute_bloom_filter(&key, "test data", &config);
        let bytes = filter.to_bytes();
        let restored = BloomFilter::from_bytes(&bytes).unwrap();
        assert_eq!(filter, restored);
    }

    #[test]
    fn bloom_different_keys_different_filters() {
        let key1 = SecretKey::from_bytes([0x42; 32]);
        let key2 = SecretKey::from_bytes([0x99; 32]);
        let config = BloomConfig::default();
        let f1 = compute_bloom_filter(&key1, "same text", &config);
        let f2 = compute_bloom_filter(&key2, "same text", &config);
        assert_ne!(f1, f2);
    }

    #[test]
    fn bloom_false_positive_rate() {
        let key = test_key();
        let config = BloomConfig {
            filter_bits: 1024,
            num_hashes: 7,
            ngram_size: 3,
        };

        let doc = compute_bloom_filter(&key, "alice@example.com", &config);
        let mut false_positives = 0;
        let total_queries = 1000;

        for i in 0..total_queries {
            let query_text = format!("nomatch{i:04}");
            let query = compute_query_filter(&key, &query_text, &config);
            if bloom_search(&doc, &query) {
                false_positives += 1;
            }
        }

        // False positive rate should be well under 1% with these parameters
        let fp_rate = false_positives as f64 / total_queries as f64;
        assert!(
            fp_rate < 0.01,
            "false positive rate too high: {:.2}%",
            fp_rate * 100.0
        );
    }

    #[test]
    fn extract_ngrams_basic() {
        let ngrams = extract_ngrams("abcde", 3);
        assert_eq!(ngrams, vec!["abc", "bcd", "cde"]);
    }

    #[test]
    fn extract_ngrams_short_text() {
        let ngrams = extract_ngrams("ab", 3);
        assert_eq!(ngrams, vec!["ab"]);
    }

    #[test]
    fn extract_ngrams_empty() {
        let ngrams = extract_ngrams("", 3);
        assert!(ngrams.is_empty());
    }
}
