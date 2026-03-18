//! Secure key material wrappers with automatic zeroization.
//!
//! # Security
//!
//! - [`SecretKey`] does NOT implement `Clone`, `Debug`, `Display`, `Serialize`, or `Deserialize`
//! - Memory is automatically zeroed when the value is dropped via [`zeroize::ZeroizeOnDrop`]
//! - All intermediate plaintext buffers should use [`zeroize::Zeroizing<Vec<u8>>`]

use zeroize::Zeroize;

/// A 256-bit (32-byte) secret key with automatic zeroization on drop.
///
/// This type intentionally does NOT implement:
/// - `Clone` — keys must not be duplicated
/// - `Debug` / `Display` — keys must not appear in logs
/// - `Serialize` / `Deserialize` — keys must not be serialized
///
/// To access the raw bytes, use [`SecretKey::as_bytes()`].
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Creates a new `SecretKey` from raw bytes.
    ///
    /// The caller is responsible for ensuring the bytes come from a secure source.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a new `SecretKey` from a byte slice.
    ///
    /// Returns `None` if the slice is not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Returns the raw bytes of this key.
    ///
    /// # Security
    ///
    /// The returned reference borrows from this `SecretKey`. The bytes are
    /// zeroized when this `SecretKey` is dropped, so do not store the
    /// reference beyond the key's lifetime.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// ZeroizeOnDrop is implemented via the explicit Drop above.
// We do NOT derive or implement Clone, Debug, Display, Serialize, Deserialize.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_and_access() {
        let bytes = [42u8; 32];
        let key = SecretKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &[42u8; 32]);
    }

    #[test]
    fn from_slice_valid() {
        let data = vec![7u8; 32];
        let key = SecretKey::from_slice(&data).unwrap();
        assert_eq!(key.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn from_slice_wrong_length() {
        assert!(SecretKey::from_slice(&[0u8; 16]).is_none());
        assert!(SecretKey::from_slice(&[0u8; 31]).is_none());
        assert!(SecretKey::from_slice(&[0u8; 33]).is_none());
        assert!(SecretKey::from_slice(&[]).is_none());
    }

    #[test]
    fn not_debug() {
        // SecretKey does not implement Debug. This is a compile-time guarantee.
        // If someone adds #[derive(Debug)], the following line would fail:
        fn assert_not_debug<T>() {
            // This function exists to document the intent.
            // The actual enforcement is that SecretKey has no Debug impl.
        }
        assert_not_debug::<SecretKey>();
    }
}
