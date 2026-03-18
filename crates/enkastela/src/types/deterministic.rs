//! Wrapper for deterministic (AES-256-SIV) encrypted field values.

use serde::{Deserialize, Serialize};

/// A field value encrypted with deterministic AES-256-SIV.
///
/// Same plaintext + key always produces the same ciphertext, enabling
/// unique constraints and exact-match lookups at the database level.
///
/// **Security trade-off**: Leaks equality (an attacker can see when two
/// values are identical).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Deterministic(String);

impl Deterministic {
    /// Wraps a wire-format ciphertext string.
    pub fn new(ciphertext: String) -> Self {
        Self(ciphertext)
    }

    /// Returns the wire-format ciphertext.
    pub fn ciphertext(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner ciphertext string.
    pub fn into_ciphertext(self) -> String {
        self.0
    }

    /// Returns whether the inner value looks like a valid enkastela ciphertext.
    pub fn is_valid_format(&self) -> bool {
        self.0.starts_with("ek:")
    }
}

// Note: Deterministic derives Hash because same plaintext = same ciphertext,
// making it safe for use as HashMap keys or in HashSets.

impl std::fmt::Display for Deterministic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[DETERMINISTIC]")
    }
}

impl From<String> for Deterministic {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn compute_hash<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn create_and_access() {
        let ct = "ek:1:v1:det_test".to_string();
        let det = Deterministic::new(ct.clone());
        assert_eq!(det.ciphertext(), ct);
    }

    #[test]
    fn equal_ciphertexts_hash_the_same() {
        let a = Deterministic::new("ek:1:v1:same".to_string());
        let b = Deterministic::new("ek:1:v1:same".to_string());
        assert_eq!(a, b);
        assert_eq!(compute_hash(&a), compute_hash(&b));
    }

    #[test]
    fn different_ciphertexts_likely_differ_in_hash() {
        let a = Deterministic::new("ek:1:v1:alpha".to_string());
        let b = Deterministic::new("ek:1:v1:beta".to_string());
        // Not guaranteed by Hash contract, but virtually certain for distinct inputs.
        assert_ne!(compute_hash(&a), compute_hash(&b));
    }

    #[test]
    fn usable_as_hashmap_key() {
        use std::collections::HashMap;
        let mut map = HashMap::new();
        let det = Deterministic::new("ek:1:v1:key".to_string());
        map.insert(det.clone(), "value");
        assert_eq!(map.get(&det), Some(&"value"));
    }

    #[test]
    fn usable_in_hashset() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let det = Deterministic::new("ek:1:v1:unique".to_string());
        assert!(set.insert(det.clone()));
        assert!(!set.insert(det)); // duplicate
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn display_hides_ciphertext() {
        let det = Deterministic::new("ek:1:v1:secret_value".to_string());
        let displayed = format!("{det}");
        assert_eq!(displayed, "[DETERMINISTIC]");
        assert!(!displayed.contains("secret_value"));
    }

    #[test]
    fn is_valid_format() {
        let valid = Deterministic::new("ek:1:v1:payload".to_string());
        assert!(valid.is_valid_format());

        let invalid = Deterministic::new("garbage".to_string());
        assert!(!invalid.is_valid_format());
    }

    #[test]
    fn serde_roundtrip() {
        let original = Deterministic::new("ek:1:v1:serde_det".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Deterministic = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);

        // transparent: serialized as a bare string
        assert_eq!(json, "\"ek:1:v1:serde_det\"");
    }

    #[test]
    fn from_string() {
        let s = "ek:1:v1:from_det".to_string();
        let det: Deterministic = s.clone().into();
        assert_eq!(det.ciphertext(), s);
    }

    #[test]
    fn into_ciphertext_consumes() {
        let ct = "ek:1:v1:consume_det".to_string();
        let det = Deterministic::new(ct.clone());
        let recovered = det.into_ciphertext();
        assert_eq!(recovered, ct);
    }
}
