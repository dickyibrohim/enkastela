//! Constant-time comparison wrappers.
//!
//! Prevents timing side-channel attacks when comparing authentication tags,
//! HMAC values, or other security-critical byte sequences.

use subtle::ConstantTimeEq;

/// Compares two byte slices in constant time.
///
/// Returns `true` if and only if the slices have the same length and identical contents.
/// The comparison time does not depend on the content of the slices, only their lengths.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(ct_eq(&[], &[]));
    }

    #[test]
    fn different_slices() {
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
    }

    #[test]
    fn different_lengths() {
        assert!(!ct_eq(b"hello", b"hell"));
        assert!(!ct_eq(&[1], &[1, 2]));
        assert!(!ct_eq(&[], &[0]));
    }
}
