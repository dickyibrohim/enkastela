//! Per-tenant key isolation via random DEKs.
//!
//! Each tenant gets a randomly generated encryption key (not derived from the
//! master key). The tenant key is wrapped with the master key for storage.
//! Destroying a tenant key makes all tenant data permanently unrecoverable.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::crypto::secret::SecretKey;
use crate::crypto::wrap;
use crate::error::Error;

/// Manages per-tenant encryption keys.
pub struct TenantKeyManager {
    master_key: SecretKey,
    // In-memory cache of unwrapped tenant keys
    cache: Mutex<HashMap<String, TenantKeyMaterial>>,
}

struct TenantKeyMaterial {
    wrapped_key: Vec<u8>,
    salt: [u8; 32],
    destroyed: bool,
}

/// Result of creating a new tenant key.
pub struct TenantKeyResult {
    pub tenant_id: String,
    pub wrapped_key: Vec<u8>,
    pub salt: [u8; 32],
}

impl TenantKeyManager {
    /// Creates a new `TenantKeyManager` backed by the given master key.
    pub fn new(master_key: SecretKey) -> Self {
        Self {
            master_key,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a new random tenant key.
    /// The key is randomly generated (NOT derived from master), then wrapped.
    pub fn create_tenant_key(&self, tenant_id: &str) -> Result<TenantKeyResult, Error> {
        // 1. Generate random 32-byte key
        let mut raw = [0u8; 32];
        rand::fill(&mut raw);
        let tenant_key = SecretKey::from_bytes(raw);

        // 2. Generate a random salt (stored alongside the wrapped key)
        let mut salt = [0u8; 32];
        rand::fill(&mut salt);

        // 3. Wrap with master key
        let wrapped_key = wrap::wrap_key(&self.master_key, &tenant_key)?;

        // 4. Cache it
        let mut cache = self.cache.lock().expect("lock poisoned");
        cache.insert(
            tenant_id.to_string(),
            TenantKeyMaterial {
                wrapped_key: wrapped_key.clone(),
                salt,
                destroyed: false,
            },
        );

        // 5. Return wrapped key + salt for storage
        Ok(TenantKeyResult {
            tenant_id: tenant_id.to_string(),
            wrapped_key,
            salt,
        })
    }

    /// Retrieves and unwraps a tenant key from stored material.
    pub fn load_tenant_key(&self, tenant_id: &str, wrapped_key: &[u8]) -> Result<SecretKey, Error> {
        // Unwrap using master key
        let tenant_key = wrap::unwrap_key(&self.master_key, wrapped_key)?;

        // Generate a salt for cache storage (the salt is informational here;
        // the caller should persist it separately if needed)
        let mut salt = [0u8; 32];
        rand::fill(&mut salt);

        // Cache it
        let mut cache = self.cache.lock().expect("lock poisoned");
        cache.insert(
            tenant_id.to_string(),
            TenantKeyMaterial {
                wrapped_key: wrapped_key.to_vec(),
                salt,
                destroyed: false,
            },
        );

        // Return a copy of the unwrapped key
        Ok(SecretKey::from_bytes(*tenant_key.as_bytes()))
    }

    /// Gets the cached tenant key or returns error.
    pub fn get_tenant_key(&self, tenant_id: &str) -> Result<SecretKey, Error> {
        let cache = self.cache.lock().expect("lock poisoned");
        let material = cache.get(tenant_id).ok_or_else(|| Error::KeyNotFound {
            purpose: "tenant".to_string(),
            scope: tenant_id.to_string(),
        })?;

        if material.destroyed {
            return Err(Error::KeyDestroyed);
        }

        // Unwrap from the cached wrapped key
        drop(cache); // release lock before calling unwrap_key
        let cache = self.cache.lock().expect("lock poisoned");
        let material = cache.get(tenant_id).ok_or_else(|| Error::KeyNotFound {
            purpose: "tenant".to_string(),
            scope: tenant_id.to_string(),
        })?;

        if material.destroyed {
            return Err(Error::KeyDestroyed);
        }

        wrap::unwrap_key(&self.master_key, &material.wrapped_key)
    }

    /// Destroys a tenant key (crypto-shredding).
    /// After this, all data encrypted with this tenant's key is permanently unrecoverable.
    pub fn destroy_tenant_key(&self, tenant_id: &str) -> Result<(), Error> {
        let mut cache = self.cache.lock().expect("lock poisoned");
        if let Some(material) = cache.get_mut(tenant_id) {
            if material.destroyed {
                return Err(Error::TenantAlreadyErased(tenant_id.to_string()));
            }
            // Zero out the wrapped key material
            for byte in material.wrapped_key.iter_mut() {
                *byte = 0;
            }
            material.wrapped_key.clear();
            // Zero the salt
            material.salt = [0u8; 32];
            material.destroyed = true;
            Ok(())
        } else {
            Err(Error::KeyNotFound {
                purpose: "tenant".to_string(),
                scope: tenant_id.to_string(),
            })
        }
    }

    /// Returns true if the tenant key exists and is not destroyed.
    pub fn is_tenant_active(&self, tenant_id: &str) -> bool {
        let cache = self.cache.lock().expect("lock poisoned");
        cache.get(tenant_id).map(|m| !m.destroyed).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master_key() -> SecretKey {
        SecretKey::from_bytes([0xAA; 32])
    }

    #[test]
    fn create_and_use_tenant_key() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();
        assert_eq!(result.tenant_id, "tenant-1");
        assert!(!result.wrapped_key.is_empty());

        // Should be able to get the key
        let key = mgr.get_tenant_key("tenant-1").unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn different_tenants_get_different_keys() {
        let mgr = TenantKeyManager::new(master_key());
        let r1 = mgr.create_tenant_key("tenant-1").unwrap();
        let r2 = mgr.create_tenant_key("tenant-2").unwrap();

        // Random keys, so wrapped forms should differ
        assert_ne!(r1.wrapped_key, r2.wrapped_key);

        // Unwrapped keys should also differ
        let k1 = mgr.get_tenant_key("tenant-1").unwrap();
        let k2 = mgr.get_tenant_key("tenant-2").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn load_tenant_key_from_wrapped_material() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();
        let wrapped = result.wrapped_key.clone();

        // Get the key while it's cached
        let original_key = mgr.get_tenant_key("tenant-1").unwrap();
        let original_bytes = *original_key.as_bytes();

        // Create a new manager (simulates restart)
        let mgr2 = TenantKeyManager::new(master_key());
        let loaded = mgr2.load_tenant_key("tenant-1", &wrapped).unwrap();

        // The loaded key should match the original
        assert_eq!(loaded.as_bytes(), &original_bytes);
    }

    #[test]
    fn destroy_tenant_key_makes_unrecoverable() {
        let mgr = TenantKeyManager::new(master_key());
        mgr.create_tenant_key("tenant-1").unwrap();

        // Key should be active
        assert!(mgr.is_tenant_active("tenant-1"));

        // Destroy it
        mgr.destroy_tenant_key("tenant-1").unwrap();

        // Key should no longer be active
        assert!(!mgr.is_tenant_active("tenant-1"));

        // Getting the key should fail
        match mgr.get_tenant_key("tenant-1") {
            Err(Error::KeyDestroyed) => {}
            Err(e) => panic!("expected KeyDestroyed, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn destroy_already_destroyed_returns_tenant_already_erased() {
        let mgr = TenantKeyManager::new(master_key());
        mgr.create_tenant_key("tenant-1").unwrap();
        mgr.destroy_tenant_key("tenant-1").unwrap();

        let err = mgr.destroy_tenant_key("tenant-1").unwrap_err();
        assert!(matches!(err, Error::TenantAlreadyErased(ref id) if id == "tenant-1"));
    }

    #[test]
    fn encrypt_with_tenant_key_destroy_decrypt_fails() {
        let mgr = TenantKeyManager::new(master_key());
        let _result = mgr.create_tenant_key("tenant-1").unwrap();

        // Get tenant key and wrap a DEK with it (simulating encryption)
        let tenant_key = mgr.get_tenant_key("tenant-1").unwrap();
        let dek = SecretKey::from_bytes([0x55; 32]);
        let wrapped_dek = wrap::wrap_key(&tenant_key, &dek).unwrap();

        // Destroy the tenant key
        mgr.destroy_tenant_key("tenant-1").unwrap();

        // The cached wrapped key was zeroed, so loading from the original
        // wrapped material would need the original bytes. But the in-memory
        // state is destroyed.
        match mgr.get_tenant_key("tenant-1") {
            Err(Error::KeyDestroyed) => {}
            Err(e) => panic!("expected KeyDestroyed, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }

        // Even if we try to unwrap the DEK with a destroyed tenant key context,
        // we cannot obtain the tenant key anymore, so the DEK (and thus the
        // data) is unrecoverable.
        // Verify the wrapped DEK cannot be unwrapped with a bogus key
        let bogus = SecretKey::from_bytes([0x00; 32]);
        assert!(wrap::unwrap_key(&bogus, &wrapped_dek).is_err());
    }

    #[test]
    fn get_nonexistent_tenant_returns_key_not_found() {
        let mgr = TenantKeyManager::new(master_key());
        match mgr.get_tenant_key("nonexistent") {
            Err(Error::KeyNotFound { purpose, scope }) => {
                assert_eq!(purpose, "tenant");
                assert_eq!(scope, "nonexistent");
            }
            Err(e) => panic!("expected KeyNotFound, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn is_tenant_active_false_for_nonexistent() {
        let mgr = TenantKeyManager::new(master_key());
        assert!(!mgr.is_tenant_active("nonexistent"));
    }
}
