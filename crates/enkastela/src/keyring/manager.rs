//! Key management orchestrator.
//!
//! Coordinates key derivation, caching, wrapping/unwrapping, and database storage.

use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{kdf, secret::SecretKey, wrap};
use crate::error::Error;
use crate::keyring::cache::KeyCache;

/// Central key management service.
///
/// Manages the lifecycle of Data Encryption Keys (DEKs): derivation from the
/// master key, wrapping for database storage, caching for performance, and
/// retrieval.
pub struct KeyringManager {
    master_key: SecretKey,
    cache: Arc<KeyCache>,
}

impl KeyringManager {
    /// Creates a new keyring manager.
    pub fn new(master_key: SecretKey, cache_ttl: Duration, cache_max: usize) -> Self {
        Self {
            master_key,
            cache: Arc::new(KeyCache::new(cache_ttl, cache_max)),
        }
    }

    /// Gets or creates a DEK for the given table and version.
    ///
    /// 1. Checks the in-memory cache first
    /// 2. If not cached, derives a new DEK from the master key using HKDF
    /// 3. Returns (DEK, wrapped_key, salt) for the caller to store if needed
    ///
    /// The `salt` and `wrapped_key` are returned so the caller can persist them.
    pub fn get_or_derive_dek(&self, table: &str, version: u32) -> Result<DekResult, Error> {
        self.get_or_derive_dek_with_salt(table, version, &kdf::generate_salt())
    }

    /// Gets or derives a DEK using a specific salt.
    ///
    /// This allows callers to provide a deterministic salt (e.g., from the
    /// database or configuration) instead of generating a random one.
    pub fn get_or_derive_dek_with_salt(
        &self,
        table: &str,
        version: u32,
        salt: &[u8; 32],
    ) -> Result<DekResult, Error> {
        let cache_key = format!("dek:{table}:v{version}");

        // Check cache first
        if let Some(key) = self.cache.get(&cache_key) {
            return Ok(DekResult {
                key,
                was_cached: true,
                wrapped_key: None,
                salt: None,
            });
        }
        let info = kdf::build_info("dek", table, version);
        let dek = kdf::derive_key(&self.master_key, salt, &info)?;

        // Wrap the DEK for storage
        let wrapped = wrap::wrap_key(&self.master_key, &dek)?;

        // Cache the DEK
        let dek_copy = SecretKey::from_bytes(*dek.as_bytes());
        self.cache.insert(cache_key, dek_copy);

        Ok(DekResult {
            key: dek,
            was_cached: false,
            wrapped_key: Some(wrapped),
            salt: Some(*salt),
        })
    }

    /// Unwraps a DEK from its stored wrapped form and caches it.
    pub fn unwrap_and_cache_dek(
        &self,
        table: &str,
        version: u32,
        wrapped_key: &[u8],
    ) -> Result<SecretKey, Error> {
        let cache_key = format!("dek:{table}:v{version}");

        // Check cache first
        if let Some(key) = self.cache.get(&cache_key) {
            return Ok(key);
        }

        // Unwrap
        let dek = wrap::unwrap_key(&self.master_key, wrapped_key)?;

        // Cache and return a copy
        let dek_copy = SecretKey::from_bytes(*dek.as_bytes());
        self.cache.insert(cache_key, dek);

        Ok(dek_copy)
    }

    /// Derives a blind index key for a specific table and column.
    pub fn derive_blind_key(
        &self,
        table: &str,
        column: &str,
        salt: &[u8],
    ) -> Result<SecretKey, Error> {
        let info = format!("enkastela:blind:{table}:{column}");
        kdf::derive_key(&self.master_key, salt, info.as_bytes())
    }

    /// Derives a 64-byte SIV key material for deterministic encryption.
    ///
    /// The returned value is wrapped in [`zeroize::Zeroizing`] to ensure
    /// key material is scrubbed from memory when dropped.
    pub fn derive_siv_key(
        &self,
        table: &str,
        version: u32,
        salt: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 64]>, Error> {
        let info = kdf::build_info("siv", table, version);
        kdf::derive_siv_key_material(&self.master_key, salt, &info)
    }

    /// Derives the audit integrity key.
    pub fn derive_audit_key(&self, salt: &[u8]) -> Result<SecretKey, Error> {
        let info = b"enkastela:audit:integrity";
        kdf::derive_key(&self.master_key, salt, info)
    }

    /// Returns a reference to the key cache.
    pub fn cache(&self) -> &KeyCache {
        &self.cache
    }

    /// Clears the key cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

/// Result of a DEK retrieval or derivation.
pub struct DekResult {
    /// The unwrapped DEK, ready for encryption/decryption.
    pub key: SecretKey,
    /// Whether the key was served from cache.
    pub was_cached: bool,
    /// The wrapped key bytes (for storage). `None` if served from cache.
    pub wrapped_key: Option<Vec<u8>>,
    /// The salt used for derivation. `None` if served from cache.
    pub salt: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> SecretKey {
        SecretKey::from_bytes([0xAA; 32])
    }

    #[test]
    fn derive_dek_and_cache() {
        let mgr = KeyringManager::new(master(), Duration::from_secs(60), 100);

        let r1 = mgr.get_or_derive_dek("users", 1).unwrap();
        assert!(!r1.was_cached);
        assert!(r1.wrapped_key.is_some());
        assert!(r1.salt.is_some());

        let r2 = mgr.get_or_derive_dek("users", 1).unwrap();
        assert!(r2.was_cached);
        assert!(r2.wrapped_key.is_none());
    }

    #[test]
    fn different_tables_different_deks() {
        let mgr = KeyringManager::new(master(), Duration::from_secs(60), 100);

        let r1 = mgr.get_or_derive_dek("users", 1).unwrap();
        mgr.clear_cache();
        let r2 = mgr.get_or_derive_dek("orders", 1).unwrap();

        assert_ne!(r1.key.as_bytes(), r2.key.as_bytes());
    }

    #[test]
    fn unwrap_and_cache() {
        let mgr = KeyringManager::new(master(), Duration::from_secs(60), 100);

        // First derive to get a wrapped key
        let r = mgr.get_or_derive_dek("users", 1).unwrap();
        let original_bytes = *r.key.as_bytes();
        let wrapped = r.wrapped_key.unwrap();

        // Clear cache, then unwrap
        mgr.clear_cache();
        let recovered = mgr.unwrap_and_cache_dek("users", 1, &wrapped).unwrap();
        assert_eq!(recovered.as_bytes(), &original_bytes);

        // Should be cached now
        assert!(mgr.cache().get("dek:users:v1").is_some());
    }

    #[test]
    fn derive_blind_key_different_columns() {
        let mgr = KeyringManager::new(master(), Duration::from_secs(60), 100);
        let salt = [0x01; 32];

        let k1 = mgr.derive_blind_key("users", "email", &salt).unwrap();
        let k2 = mgr.derive_blind_key("users", "phone", &salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_siv_key_is_64_bytes() {
        let mgr = KeyringManager::new(master(), Duration::from_secs(60), 100);
        let salt = [0x01; 32];
        let km = mgr.derive_siv_key("users", 1, &salt).unwrap();
        assert_eq!(km.len(), 64);
    }
}
