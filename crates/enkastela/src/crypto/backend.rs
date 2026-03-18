//! Pluggable cryptographic backend abstraction.
//!
//! Provides a trait [`CryptoBackend`] that abstracts over the underlying
//! crypto library. Two implementations are available:
//!
//! - **RustCrypto** (default) — uses audited RustCrypto crates
//! - **FIPS** (feature `fips`) — uses `aws-lc-rs`, a FIPS-140-2 validated backend
//!
//! The active backend is selected at compile time via feature flags.

use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;
use crate::error::Error;

/// Trait abstracting cryptographic operations over different backends.
///
/// Implementors provide AES-256-GCM, HMAC-SHA256, and HKDF-SHA256 operations.
/// All methods are `&self` to allow stateless, zero-cost dispatch.
pub trait CryptoBackend: Send + Sync {
    /// Encrypts plaintext using AES-256-GCM with a random nonce.
    ///
    /// Returns `nonce(12B) || ciphertext || tag(16B)`.
    fn aead_encrypt(&self, key: &SecretKey, plaintext: &[u8], aad: &[u8])
        -> Result<Vec<u8>, Error>;

    /// Decrypts AES-256-GCM ciphertext.
    ///
    /// Input: `nonce(12B) || ciphertext || tag(16B)`.
    fn aead_decrypt(
        &self,
        key: &SecretKey,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error>;

    /// Computes HMAC-SHA256.
    fn hmac_sha256(&self, key: &SecretKey, data: &[u8], context: &[u8]) -> Result<[u8; 32], Error>;

    /// Derives a key using HKDF-SHA256.
    fn hkdf_derive(
        &self,
        master_key: &SecretKey,
        salt: &[u8],
        info: &[u8],
    ) -> Result<SecretKey, Error>;

    /// Returns the backend name for diagnostics.
    fn name(&self) -> &'static str;

    /// Returns whether this backend is FIPS-140 validated.
    fn is_fips(&self) -> bool;
}

/// The default RustCrypto backend.
///
/// Uses `aes-gcm`, `hmac`, `sha2`, and `hkdf` crates from the audited
/// RustCrypto ecosystem.
#[derive(Debug, Clone, Copy)]
pub struct RustCryptoBackend;

impl CryptoBackend for RustCryptoBackend {
    fn aead_encrypt(
        &self,
        key: &SecretKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        crate::crypto::aead::encrypt(key, plaintext, aad)
    }

    fn aead_decrypt(
        &self,
        key: &SecretKey,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        crate::crypto::aead::decrypt(key, ciphertext, aad)
    }

    fn hmac_sha256(&self, key: &SecretKey, data: &[u8], context: &[u8]) -> Result<[u8; 32], Error> {
        crate::crypto::hmac::compute_blind_index(key, data, context)
    }

    fn hkdf_derive(
        &self,
        master_key: &SecretKey,
        salt: &[u8],
        info: &[u8],
    ) -> Result<SecretKey, Error> {
        crate::crypto::kdf::derive_key(master_key, salt, info)
    }

    fn name(&self) -> &'static str {
        "RustCrypto"
    }

    fn is_fips(&self) -> bool {
        false
    }
}

/// FIPS-140-2 validated backend using `aws-lc-rs`.
///
/// AWS-LC is a general-purpose cryptographic library maintained by AWS.
/// It has been validated under FIPS 140-2 (certificate #4631).
///
/// This backend provides the same operations as [`RustCryptoBackend`] but
/// delegates to FIPS-validated implementations.
///
/// # Feature
///
/// Requires the `fips` feature flag.
#[cfg(feature = "fips")]
#[derive(Debug, Clone, Copy)]
pub struct FipsBackend;

#[cfg(feature = "fips")]
impl CryptoBackend for FipsBackend {
    fn aead_encrypt(
        &self,
        key: &SecretKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

        let unbound =
            UnboundKey::new(&AES_256_GCM, key.as_bytes()).map_err(|_| Error::EncryptionFailed)?;
        let sealing_key = LessSafeKey::new(unbound);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        aws_lc_rs::rand::fill(&mut nonce_bytes).map_err(|_| Error::EncryptionFailed)?;

        let mut in_out = plaintext.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(
                Nonce::try_assume_unique_for_key(&nonce_bytes)
                    .map_err(|_| Error::EncryptionFailed)?,
                Aad::from(aad),
                &mut in_out,
            )
            .map_err(|_| Error::EncryptionFailed)?;

        let mut output = Vec::with_capacity(12 + in_out.len() + 16);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&in_out);
        output.extend_from_slice(tag.as_ref());
        Ok(output)
    }

    fn aead_decrypt(
        &self,
        key: &SecretKey,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

        if ciphertext.len() < 28 {
            return Err(Error::DecryptionFailed);
        }

        let (nonce_bytes, ct_with_tag) = ciphertext.split_at(12);
        let nonce =
            Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| Error::DecryptionFailed)?;

        let unbound =
            UnboundKey::new(&AES_256_GCM, key.as_bytes()).map_err(|_| Error::DecryptionFailed)?;
        let opening_key = LessSafeKey::new(unbound);

        let mut in_out = ct_with_tag.to_vec();
        let plaintext = opening_key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| Error::DecryptionFailed)?;

        Ok(Zeroizing::new(plaintext.to_vec()))
    }

    fn hmac_sha256(&self, key: &SecretKey, data: &[u8], context: &[u8]) -> Result<[u8; 32], Error> {
        use aws_lc_rs::hmac;

        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
        let mut ctx = hmac::Context::with_key(&signing_key);
        ctx.update(context);
        ctx.update(data);
        let tag = ctx.sign();
        let mut output = [0u8; 32];
        output.copy_from_slice(tag.as_ref());
        Ok(output)
    }

    fn hkdf_derive(
        &self,
        master_key: &SecretKey,
        salt: &[u8],
        info: &[u8],
    ) -> Result<SecretKey, Error> {
        use aws_lc_rs::hkdf;

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = salt.extract(master_key.as_bytes());
        let info_slice = [info];
        let okm = prk
            .expand(&info_slice, HkdfLen(32))
            .map_err(|_| Error::KeyDerivationFailed)?;
        let mut key_bytes = [0u8; 32];
        okm.fill(&mut key_bytes)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(SecretKey::from_bytes(key_bytes))
    }

    fn name(&self) -> &'static str {
        "aws-lc-rs (FIPS-140-2)"
    }

    fn is_fips(&self) -> bool {
        true
    }
}

#[cfg(feature = "fips")]
struct HkdfLen(usize);

#[cfg(feature = "fips")]
impl aws_lc_rs::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Returns the default crypto backend for the current build configuration.
///
/// - With `fips` feature: returns [`FipsBackend`]
/// - Without `fips` feature: returns [`RustCryptoBackend`]
pub fn default_backend() -> &'static dyn CryptoBackend {
    #[cfg(feature = "fips")]
    {
        &FipsBackend
    }
    #[cfg(not(feature = "fips"))]
    {
        &RustCryptoBackend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustcrypto_backend_name() {
        let backend = RustCryptoBackend;
        assert_eq!(backend.name(), "RustCrypto");
        assert!(!backend.is_fips());
    }

    #[test]
    fn rustcrypto_aead_roundtrip() {
        let backend = RustCryptoBackend;
        let key = SecretKey::from_bytes([0x42; 32]);
        let ct = backend.aead_encrypt(&key, b"hello", b"aad").unwrap();
        let pt = backend.aead_decrypt(&key, &ct, b"aad").unwrap();
        assert_eq!(&*pt, b"hello");
    }

    #[test]
    fn rustcrypto_hmac_deterministic() {
        let backend = RustCryptoBackend;
        let key = SecretKey::from_bytes([0x42; 32]);
        let h1 = backend.hmac_sha256(&key, b"data", b"ctx").unwrap();
        let h2 = backend.hmac_sha256(&key, b"data", b"ctx").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn rustcrypto_hkdf_deterministic() {
        let backend = RustCryptoBackend;
        let mk = SecretKey::from_bytes([0x42; 32]);
        let d1 = backend.hkdf_derive(&mk, &[0; 32], b"info").unwrap();
        let d2 = backend.hkdf_derive(&mk, &[0; 32], b"info").unwrap();
        assert_eq!(d1.as_bytes(), d2.as_bytes());
    }

    #[test]
    fn default_backend_is_rustcrypto() {
        let backend = default_backend();
        #[cfg(not(feature = "fips"))]
        assert_eq!(backend.name(), "RustCrypto");
        #[cfg(feature = "fips")]
        assert_eq!(backend.name(), "aws-lc-rs (FIPS-140-2)");
    }
}
