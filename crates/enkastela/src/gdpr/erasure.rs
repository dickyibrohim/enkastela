//! Crypto-shredding for GDPR right to erasure (Article 17).
//!
//! Destroying a tenant's encryption key makes all their encrypted data
//! permanently unrecoverable, satisfying the right to erasure requirement
//! without needing to find and delete individual records.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::tenant::manager::TenantKeyManager;

/// Proof that a tenant's key material was destroyed.
#[derive(Debug, Clone)]
pub struct ErasureProof {
    /// SHA-256 hash of the wrapped key before destruction.
    pub pre_destruction_hash: [u8; 32],
    /// Timestamp of destruction.
    pub destroyed_at: DateTime<Utc>,
}

/// Receipt issued after a successful crypto-shredding operation.
#[derive(Debug, Clone)]
pub struct ErasureReceipt {
    pub tenant_id: String,
    pub proof: ErasureProof,
    pub issued_at: DateTime<Utc>,
}

/// Performs crypto-shredding: destroys a tenant's key making all their data unrecoverable.
pub fn erase_tenant(
    tenant_mgr: &TenantKeyManager,
    tenant_id: &str,
    wrapped_key: &[u8],
) -> Result<ErasureReceipt, Error> {
    // 1. Hash the wrapped key (pre-destruction proof)
    let mut hasher = Sha256::new();
    hasher.update(wrapped_key);
    let pre_hash: [u8; 32] = hasher.finalize().into();

    // 2. Destroy the tenant key
    tenant_mgr.destroy_tenant_key(tenant_id)?;

    let now = Utc::now();

    // 3. Issue receipt
    Ok(ErasureReceipt {
        tenant_id: tenant_id.to_string(),
        proof: ErasureProof {
            pre_destruction_hash: pre_hash,
            destroyed_at: now,
        },
        issued_at: now,
    })
}

/// Verifies an erasure receipt by checking the pre-destruction hash matches.
pub fn verify_receipt(receipt: &ErasureReceipt, original_wrapped_key: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(original_wrapped_key);
    let computed: [u8; 32] = hasher.finalize().into();
    crate::crypto::constant_time::ct_eq(&computed, &receipt.proof.pre_destruction_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::SecretKey;
    use crate::tenant::manager::TenantKeyManager;

    fn master_key() -> SecretKey {
        SecretKey::from_bytes([0xBB; 32])
    }

    #[test]
    fn erase_tenant_produces_valid_receipt() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();

        let receipt = erase_tenant(&mgr, "tenant-1", &result.wrapped_key).unwrap();
        assert_eq!(receipt.tenant_id, "tenant-1");
        assert!(receipt.proof.destroyed_at <= receipt.issued_at);
    }

    #[test]
    fn receipt_contains_correct_pre_destruction_hash() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();
        let wrapped = result.wrapped_key.clone();

        let receipt = erase_tenant(&mgr, "tenant-1", &wrapped).unwrap();

        // Manually compute expected hash
        let mut hasher = Sha256::new();
        hasher.update(&wrapped);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(receipt.proof.pre_destruction_hash, expected);
    }

    #[test]
    fn verify_receipt_with_correct_key_succeeds() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();
        let wrapped = result.wrapped_key.clone();

        let receipt = erase_tenant(&mgr, "tenant-1", &wrapped).unwrap();

        assert!(verify_receipt(&receipt, &wrapped));
    }

    #[test]
    fn verify_receipt_with_wrong_key_fails() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();

        let receipt = erase_tenant(&mgr, "tenant-1", &result.wrapped_key).unwrap();

        let wrong_key = vec![0xFF; 40];
        assert!(!verify_receipt(&receipt, &wrong_key));
    }

    #[test]
    fn double_erasure_returns_tenant_already_erased() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();
        let wrapped = result.wrapped_key.clone();

        erase_tenant(&mgr, "tenant-1", &wrapped).unwrap();

        let err = erase_tenant(&mgr, "tenant-1", &wrapped).unwrap_err();
        assert!(matches!(err, Error::TenantAlreadyErased(ref id) if id == "tenant-1"));
    }

    #[test]
    fn tenant_key_inaccessible_after_erasure() {
        let mgr = TenantKeyManager::new(master_key());
        let result = mgr.create_tenant_key("tenant-1").unwrap();

        erase_tenant(&mgr, "tenant-1", &result.wrapped_key).unwrap();

        // The tenant key should now be destroyed
        assert!(!mgr.is_tenant_active("tenant-1"));
        match mgr.get_tenant_key("tenant-1") {
            Err(Error::KeyDestroyed) => {}
            Err(e) => panic!("expected KeyDestroyed, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
