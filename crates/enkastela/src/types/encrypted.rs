//! Wrapper for randomized (AES-256-GCM) encrypted field values.

use serde::{Deserialize, Serialize};

/// A field value that is encrypted using randomized AES-256-GCM.
///
/// Each encryption produces a different ciphertext, providing the strongest
/// security guarantee (IND-CPA). Use this for most sensitive fields.
///
/// The inner `String` holds the wire-format ciphertext (`ek:1:v{n}:...`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Encrypted(String);

impl Encrypted {
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

impl std::fmt::Display for Encrypted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ENCRYPTED]")
    }
}

impl From<String> for Encrypted {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for Encrypted {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_access_ciphertext() {
        let ct = "ek:1:v1:abc123".to_string();
        let enc = Encrypted::new(ct.clone());
        assert_eq!(enc.ciphertext(), ct);
    }

    #[test]
    fn display_hides_ciphertext() {
        let enc = Encrypted::new("ek:1:v1:super_secret_data".to_string());
        let displayed = format!("{enc}");
        assert_eq!(displayed, "[ENCRYPTED]");
        assert!(!displayed.contains("super_secret_data"));
    }

    #[test]
    fn is_valid_format_accepts_ek_prefix() {
        let valid = Encrypted::new("ek:1:v1:payload".to_string());
        assert!(valid.is_valid_format());

        let invalid = Encrypted::new("not_a_valid_ciphertext".to_string());
        assert!(!invalid.is_valid_format());
    }

    #[test]
    fn serde_roundtrip() {
        let original = Encrypted::new("ek:1:v1:roundtrip_test".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Encrypted = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);

        // transparent: serialized as a bare string, not an object
        assert_eq!(json, "\"ek:1:v1:roundtrip_test\"");
    }

    #[test]
    fn from_string() {
        let s = "ek:1:v1:from_test".to_string();
        let enc: Encrypted = s.clone().into();
        assert_eq!(enc.ciphertext(), s);
    }

    #[test]
    fn into_ciphertext_consumes() {
        let ct = "ek:1:v1:consume".to_string();
        let enc = Encrypted::new(ct.clone());
        let recovered = enc.into_ciphertext();
        assert_eq!(recovered, ct);
    }

    #[test]
    fn as_ref_str() {
        let enc = Encrypted::new("ek:1:v1:asref".to_string());
        let r: &str = enc.as_ref();
        assert_eq!(r, "ek:1:v1:asref");
    }
}
