//! Wire format v1 encode/decode.
//!
//! # Format
//!
//! ```text
//! ek:{format_version}:v{dek_version}:{base64url(nonce || ciphertext || tag)}
//! ```
//!
//! Example: `ek:1:v3:dGhpcyBpcyBub3QgcmVhbCBjaXBoZXJ0ZXh0`
//!
//! - `ek:` — 3-byte prefix identifying enkastela-managed data
//! - `{format_version}` — wire format version (always `1` for v1.0)
//! - `v{dek_version}` — DEK version used for encryption
//! - Base64URL-encoded binary payload: `nonce(12B) || ciphertext || tag(16B)`

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::crypto::aead::MIN_CIPHERTEXT_SIZE;
use crate::error::Error;

/// Wire format prefix.
const PREFIX: &str = "ek:";

/// Current wire format version.
pub const FORMAT_VERSION: u32 = 1;

/// A decoded wire format payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePayload {
    /// Wire format version (always 1 for v1.0).
    pub format_version: u32,
    /// DEK version used for encryption.
    pub dek_version: u32,
    /// Raw binary: nonce(12B) || ciphertext || tag(16B).
    pub raw_ciphertext: Vec<u8>,
}

impl WirePayload {
    /// Creates a new wire payload with format version 1.
    pub fn new(dek_version: u32, raw_ciphertext: Vec<u8>) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            dek_version,
            raw_ciphertext,
        }
    }

    /// Encodes this payload to the wire format string.
    ///
    /// Output: `ek:1:v{dek_version}:{base64url(raw_ciphertext)}`
    pub fn encode(&self) -> String {
        let b64 = URL_SAFE_NO_PAD.encode(&self.raw_ciphertext);
        format!("ek:{}:v{}:{}", self.format_version, self.dek_version, b64)
    }

    /// Decodes a wire format string into a [`WirePayload`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWireFormat`] for any parsing failure, or
    /// [`Error::UnsupportedFormatVersion`] for unknown format versions.
    pub fn decode(s: &str) -> Result<Self, Error> {
        // Must start with "ek:"
        let rest = s.strip_prefix(PREFIX).ok_or(Error::InvalidWireFormat)?;

        // Split: format_version ":" rest
        let (fmt_ver_str, rest) = rest.split_once(':').ok_or(Error::InvalidWireFormat)?;
        let format_version: u32 = fmt_ver_str.parse().map_err(|_| Error::InvalidWireFormat)?;

        if format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion(format_version));
        }

        // Split: "v{dek_version}" ":" base64
        let (dek_ver_str, b64) = rest.split_once(':').ok_or(Error::InvalidWireFormat)?;

        // Must start with "v"
        let dek_ver_num = dek_ver_str
            .strip_prefix('v')
            .ok_or(Error::InvalidWireFormat)?;
        let dek_version: u32 = dek_ver_num.parse().map_err(|_| Error::InvalidWireFormat)?;

        if dek_version == 0 {
            return Err(Error::InvalidWireFormat);
        }

        // Decode base64url
        let raw_ciphertext = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| Error::InvalidWireFormat)?;

        // Minimum size: nonce(12) + tag(16) = 28 bytes
        if raw_ciphertext.len() < MIN_CIPHERTEXT_SIZE {
            return Err(Error::InvalidWireFormat);
        }

        Ok(Self {
            format_version,
            dek_version,
            raw_ciphertext,
        })
    }

    /// Quick check whether a string looks like enkastela-encrypted data.
    ///
    /// Only checks the prefix — does not validate the full format.
    #[inline]
    pub fn is_encrypted(s: &str) -> bool {
        s.starts_with(PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ciphertext() -> Vec<u8> {
        // 12 (nonce) + 5 (ciphertext body) + 16 (tag) = 33 bytes
        vec![0xAA; 33]
    }

    #[test]
    fn encode_decode_roundtrip() {
        let payload = WirePayload::new(3, sample_ciphertext());
        let encoded = payload.encode();
        let decoded = WirePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_format() {
        let payload = WirePayload::new(1, vec![0; MIN_CIPHERTEXT_SIZE]);
        let encoded = payload.encode();
        assert!(encoded.starts_with("ek:1:v1:"));
    }

    #[test]
    fn decode_rejects_missing_prefix() {
        assert!(WirePayload::decode("xx:1:v1:AAAA").is_err());
    }

    #[test]
    fn decode_rejects_wrong_prefix() {
        assert!(WirePayload::decode("vault:1:v1:AAAA").is_err());
    }

    #[test]
    fn decode_rejects_unsupported_format_version() {
        // Build valid base64 of 28+ bytes
        let b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 28]);
        let s = format!("ek:99:v1:{b64}");
        match WirePayload::decode(&s) {
            Err(Error::UnsupportedFormatVersion(99)) => {}
            other => panic!("expected UnsupportedFormatVersion(99), got {:?}", other),
        }
    }

    #[test]
    fn decode_rejects_missing_dek_version() {
        let b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 28]);
        assert!(WirePayload::decode(&format!("ek:1:{b64}")).is_err());
    }

    #[test]
    fn decode_rejects_dek_version_without_v_prefix() {
        let b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 28]);
        assert!(WirePayload::decode(&format!("ek:1:3:{b64}")).is_err());
    }

    #[test]
    fn decode_rejects_dek_version_zero() {
        let b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 28]);
        assert!(WirePayload::decode(&format!("ek:1:v0:{b64}")).is_err());
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        assert!(WirePayload::decode("ek:1:v1:!!!not-base64!!!").is_err());
    }

    #[test]
    fn decode_rejects_payload_too_short() {
        // 27 bytes < 28 minimum
        let b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 27]);
        assert!(WirePayload::decode(&format!("ek:1:v1:{b64}")).is_err());
    }

    #[test]
    fn decode_rejects_empty_payload() {
        let b64 = URL_SAFE_NO_PAD.encode(vec![0u8; 0]);
        assert!(WirePayload::decode(&format!("ek:1:v1:{b64}")).is_err());
    }

    #[test]
    fn is_encrypted_true() {
        assert!(WirePayload::is_encrypted("ek:1:v1:AAAA"));
    }

    #[test]
    fn is_encrypted_false_for_plaintext() {
        assert!(!WirePayload::is_encrypted("hello world"));
        assert!(!WirePayload::is_encrypted(""));
    }

    #[test]
    fn is_encrypted_false_for_partial_prefix() {
        assert!(!WirePayload::is_encrypted("ek"));
        assert!(!WirePayload::is_encrypted("e"));
        assert!(!WirePayload::is_encrypted(""));
    }

    #[test]
    fn is_encrypted_true_for_prefix_with_any_suffix() {
        // Anything starting with "ek:" is considered encrypted (quick check only)
        assert!(WirePayload::is_encrypted("ek:"));
        assert!(WirePayload::is_encrypted("ek:garbage"));
    }

    #[test]
    fn base64url_no_plus_or_slash() {
        // Create ciphertext that would produce + and / in standard base64
        let ct: Vec<u8> = (0..=255).cycle().take(100).collect();
        let payload = WirePayload::new(1, ct);
        let encoded = payload.encode();
        // The base64 part should not contain + or /
        let b64_part = encoded.rsplit(':').next().unwrap();
        assert!(!b64_part.contains('+'), "base64url should not contain '+'");
        assert!(!b64_part.contains('/'), "base64url should not contain '/'");
    }

    #[test]
    fn format_version_and_dek_version_independent() {
        let ct = sample_ciphertext();
        let p1 = WirePayload::new(1, ct.clone());
        let p5 = WirePayload::new(5, ct);

        let d1 = WirePayload::decode(&p1.encode()).unwrap();
        let d5 = WirePayload::decode(&p5.encode()).unwrap();

        assert_eq!(d1.format_version, 1);
        assert_eq!(d1.dek_version, 1);
        assert_eq!(d5.format_version, 1);
        assert_eq!(d5.dek_version, 5);
    }

    #[test]
    fn decode_minimum_valid_payload() {
        // Exactly 28 bytes (nonce + tag, no ciphertext body = empty plaintext)
        let b64 = URL_SAFE_NO_PAD.encode(vec![0u8; MIN_CIPHERTEXT_SIZE]);
        let decoded = WirePayload::decode(&format!("ek:1:v1:{b64}")).unwrap();
        assert_eq!(decoded.raw_ciphertext.len(), MIN_CIPHERTEXT_SIZE);
    }
}
