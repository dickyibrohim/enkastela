//! Wrapper for searchable encrypted fields (randomized encryption + blind index).

use serde::{Deserialize, Serialize};

/// Encode a byte slice as a lowercase hexadecimal string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A field that is both encrypted (AES-256-GCM) and searchable via blind index.
///
/// Stores the encrypted ciphertext and a precomputed HMAC-SHA256 blind index
/// for equality searches without decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Searchable {
    /// Wire-format encrypted value.
    ciphertext: String,
    /// Hex-encoded blind index (HMAC-SHA256).
    blind_index: String,
}

impl Searchable {
    /// Creates a new searchable value from a ciphertext and a raw 32-byte blind index.
    pub fn new(ciphertext: String, blind_index: [u8; 32]) -> Self {
        Self {
            ciphertext,
            blind_index: hex_encode(&blind_index),
        }
    }

    /// Returns the wire-format encrypted ciphertext.
    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }

    /// Returns the hex-encoded blind index.
    pub fn blind_index(&self) -> &str {
        &self.blind_index
    }

    /// Consumes self and returns `(ciphertext, blind_index)`.
    pub fn into_parts(self) -> (String, String) {
        (self.ciphertext, self.blind_index)
    }
}

impl std::fmt::Display for Searchable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[SEARCHABLE:{}]", &self.blind_index[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_index() -> [u8; 32] {
        [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80,
        ]
    }

    #[test]
    fn create_and_access_parts() {
        let ct = "ek:1:v1:searchable_ct".to_string();
        let idx = sample_index();
        let s = Searchable::new(ct.clone(), idx);
        assert_eq!(s.ciphertext(), ct);
        assert_eq!(s.blind_index(), hex_encode(&idx));
    }

    #[test]
    fn display_shows_truncated_index_not_ciphertext() {
        let s = Searchable::new("ek:1:v1:secret".to_string(), sample_index());
        let displayed = format!("{s}");
        // First 4 bytes = "abcdef01", shown as 8 hex chars
        assert_eq!(displayed, "[SEARCHABLE:abcdef01]");
        assert!(!displayed.contains("secret"));
    }

    #[test]
    fn into_parts_returns_both() {
        let ct = "ek:1:v1:parts_test".to_string();
        let idx = sample_index();
        let expected_hex = hex_encode(&idx);
        let s = Searchable::new(ct.clone(), idx);
        let (got_ct, got_idx) = s.into_parts();
        assert_eq!(got_ct, ct);
        assert_eq!(got_idx, expected_hex);
    }

    #[test]
    fn serde_roundtrip() {
        let original = Searchable::new("ek:1:v1:serde_test".to_string(), sample_index());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Searchable = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);

        // Ensure both fields are present in serialized form
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("ciphertext").is_some());
        assert!(value.get("blind_index").is_some());
    }

    #[test]
    fn hex_encode_correctness() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x0a, 0xb3]), "00ff0ab3");
        assert_eq!(hex_encode(&[]), "");
    }
}
