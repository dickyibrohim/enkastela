//! Input validation for security-critical operations.
//!
//! Enforces constraints on:
//! - Payload size (prevent DoS via large allocations)
//! - Key version ranges
//! - AAD format

use crate::error::Error;

/// Maximum plaintext payload size: 16 MiB.
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Validates that a plaintext payload does not exceed the maximum size.
pub fn validate_payload_size(payload: &[u8]) -> Result<(), Error> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(Error::PayloadTooLarge {
            max_bytes: MAX_PAYLOAD_SIZE,
        });
    }
    Ok(())
}

/// Validates that a key version is in the acceptable range (1..=u32::MAX).
pub fn validate_key_version(version: u32) -> Result<(), Error> {
    if version == 0 {
        return Err(Error::InvalidInput(
            "key version must be >= 1 (version 0 is reserved)".into(),
        ));
    }
    Ok(())
}

/// Validates AAD format — must be non-empty.
pub fn validate_aad(aad: &[u8]) -> Result<(), Error> {
    if aad.is_empty() {
        return Err(Error::InvalidInput(
            "AAD must not be empty (should contain table:column)".into(),
        ));
    }
    Ok(())
}

/// Builds AAD from table and column names using length-prefixed encoding.
///
/// Format: `{table_len_u16_be}{table}{column}` — unambiguous even if names
/// contain colons or other special characters.
pub fn build_aad(table: &str, column: &str) -> Vec<u8> {
    let table_bytes = table.as_bytes();
    let column_bytes = column.as_bytes();
    let table_len = (table_bytes.len() as u16).to_be_bytes();

    let mut aad = Vec::with_capacity(2 + table_bytes.len() + column_bytes.len());
    aad.extend_from_slice(&table_len);
    aad.extend_from_slice(table_bytes);
    aad.extend_from_slice(column_bytes);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_payload_size() {
        assert!(validate_payload_size(&[0u8; 100]).is_ok());
        assert!(validate_payload_size(&[0u8; MAX_PAYLOAD_SIZE]).is_ok());
        assert!(validate_payload_size(&[]).is_ok());
    }

    #[test]
    fn payload_too_large() {
        let big = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(validate_payload_size(&big).is_err());
    }

    #[test]
    fn valid_key_version() {
        assert!(validate_key_version(1).is_ok());
        assert!(validate_key_version(100).is_ok());
        assert!(validate_key_version(u32::MAX).is_ok());
    }

    #[test]
    fn invalid_key_version_zero() {
        assert!(validate_key_version(0).is_err());
    }

    #[test]
    fn valid_aad() {
        assert!(validate_aad(b"users:email").is_ok());
    }

    #[test]
    fn empty_aad_rejected() {
        assert!(validate_aad(b"").is_err());
    }

    #[test]
    fn build_aad_format() {
        let aad = build_aad("users", "email");
        // Length-prefixed: u16 BE length of "users" (5) + "users" + "email"
        let mut expected = vec![0x00, 0x05]; // 5 in big-endian u16
        expected.extend_from_slice(b"users");
        expected.extend_from_slice(b"email");
        assert_eq!(aad, expected);
    }

    #[test]
    fn build_aad_no_delimiter_collision() {
        // "a:b" + "c" vs "a" + "b:c" must produce different AADs
        let aad1 = build_aad("a:b", "c");
        let aad2 = build_aad("a", "b:c");
        assert_ne!(aad1, aad2);
    }
}
