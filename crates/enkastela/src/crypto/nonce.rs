//! CSPRNG nonce generation for AES-GCM.
//!
//! Generates 96-bit (12-byte) random nonces using the operating system's
//! cryptographically secure random number generator.

/// Size of an AES-GCM nonce in bytes (96 bits).
pub const NONCE_SIZE: usize = 12;

/// Generates a random 96-bit nonce from the OS CSPRNG.
///
/// # Panics
///
/// Panics if the OS CSPRNG is unavailable. This is a deliberate fail-closed
/// design — using a weak nonce source would compromise all encryption.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::fill(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn nonce_is_12_bytes() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn nonce_is_not_zero() {
        let nonce = generate_nonce();
        // Probability of all-zero 12-byte nonce is 2^-96, effectively impossible
        assert_ne!(nonce, [0u8; 12]);
    }

    #[test]
    fn nonces_are_unique_10000() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let nonce = generate_nonce();
            assert!(seen.insert(nonce), "nonce collision detected");
        }
    }
}
