//! Multi-master key support.
//!
//! Allows multiple master key providers — one per environment, compliance
//! boundary, or key escrow. Key entries in the database record which master
//! key ID was used, enabling seamless migration between providers.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::crypto::secret::SecretKey;
use crate::error::Error;
use crate::keyring::provider::MasterKeyProvider;

/// Identifier for a master key provider.
pub type ProviderId = String;

/// A hierarchy of master key providers.
///
/// Maintains multiple named providers and selects the appropriate one
/// based on the provider ID. One provider is designated as the "primary"
/// for new encryptions.
pub struct KeyHierarchy {
    /// Named providers.
    providers: HashMap<ProviderId, Arc<dyn MasterKeyProvider>>,
    /// Primary provider ID for new encryptions.
    primary_id: ProviderId,
}

impl KeyHierarchy {
    /// Creates a new key hierarchy with a primary provider.
    pub fn new(primary_id: &str, primary: impl MasterKeyProvider + 'static) -> Self {
        let mut providers = HashMap::new();
        providers.insert(
            primary_id.to_string(),
            Arc::new(primary) as Arc<dyn MasterKeyProvider>,
        );
        Self {
            providers,
            primary_id: primary_id.to_string(),
        }
    }

    /// Adds a secondary provider.
    pub fn add_provider(&mut self, id: &str, provider: impl MasterKeyProvider + 'static) {
        self.providers.insert(
            id.to_string(),
            Arc::new(provider) as Arc<dyn MasterKeyProvider>,
        );
    }

    /// Sets the primary provider for new encryptions.
    pub fn set_primary(&mut self, id: &str) -> Result<(), Error> {
        if !self.providers.contains_key(id) {
            return Err(Error::Config(format!(
                "provider '{}' not found in hierarchy",
                id
            )));
        }
        self.primary_id = id.to_string();
        Ok(())
    }

    /// Returns the primary provider ID.
    pub fn primary_id(&self) -> &str {
        &self.primary_id
    }

    /// Returns the primary master key.
    pub async fn get_primary_key(&self) -> Result<SecretKey, Error> {
        let provider = self
            .providers
            .get(&self.primary_id)
            .ok_or_else(|| Error::Config("primary provider not found".into()))?;
        provider.get_master_key().await
    }

    /// Returns a master key from a specific provider.
    pub async fn get_key(&self, provider_id: &str) -> Result<SecretKey, Error> {
        let provider = self
            .providers
            .get(provider_id)
            .ok_or_else(|| Error::Config(format!("provider '{}' not found", provider_id)))?;
        provider.get_master_key().await
    }

    /// Returns all provider IDs.
    pub fn provider_ids(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Returns the number of providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

/// Wraps a KeyHierarchy as a MasterKeyProvider (returns primary key).
pub struct HierarchyProvider {
    hierarchy: Arc<KeyHierarchy>,
}

impl HierarchyProvider {
    pub fn new(hierarchy: Arc<KeyHierarchy>) -> Self {
        Self { hierarchy }
    }
}

#[async_trait]
impl MasterKeyProvider for HierarchyProvider {
    async fn get_master_key(&self) -> Result<SecretKey, Error> {
        self.hierarchy.get_primary_key().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::provider::StaticKeyProvider;

    fn key_a() -> SecretKey {
        SecretKey::from_bytes([0xAA; 32])
    }

    fn key_b() -> SecretKey {
        SecretKey::from_bytes([0xBB; 32])
    }

    #[tokio::test]
    async fn hierarchy_primary_key() {
        let hierarchy = KeyHierarchy::new("prod", StaticKeyProvider::new(key_a()));
        let key = hierarchy.get_primary_key().await.unwrap();
        assert_eq!(key.as_bytes(), key_a().as_bytes());
    }

    #[tokio::test]
    async fn hierarchy_multiple_providers() {
        let mut hierarchy = KeyHierarchy::new("prod", StaticKeyProvider::new(key_a()));
        hierarchy.add_provider("staging", StaticKeyProvider::new(key_b()));

        let prod_key = hierarchy.get_key("prod").await.unwrap();
        let staging_key = hierarchy.get_key("staging").await.unwrap();

        assert_eq!(prod_key.as_bytes(), key_a().as_bytes());
        assert_eq!(staging_key.as_bytes(), key_b().as_bytes());
        assert_ne!(prod_key.as_bytes(), staging_key.as_bytes());
    }

    #[tokio::test]
    async fn hierarchy_switch_primary() {
        let mut hierarchy = KeyHierarchy::new("old", StaticKeyProvider::new(key_a()));
        hierarchy.add_provider("new", StaticKeyProvider::new(key_b()));

        assert_eq!(hierarchy.primary_id(), "old");

        hierarchy.set_primary("new").unwrap();
        assert_eq!(hierarchy.primary_id(), "new");

        let key = hierarchy.get_primary_key().await.unwrap();
        assert_eq!(key.as_bytes(), key_b().as_bytes());
    }

    #[tokio::test]
    async fn hierarchy_unknown_provider_fails() {
        let hierarchy = KeyHierarchy::new("prod", StaticKeyProvider::new(key_a()));
        let result = hierarchy.get_key("nonexistent").await;
        assert!(result.is_err());
    }

    #[test]
    fn hierarchy_set_primary_unknown_fails() {
        let mut hierarchy = KeyHierarchy::new("prod", StaticKeyProvider::new(key_a()));
        let result = hierarchy.set_primary("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn hierarchy_provider_count() {
        let mut hierarchy = KeyHierarchy::new("a", StaticKeyProvider::new(key_a()));
        assert_eq!(hierarchy.provider_count(), 1);
        hierarchy.add_provider("b", StaticKeyProvider::new(key_b()));
        assert_eq!(hierarchy.provider_count(), 2);
    }

    #[tokio::test]
    async fn hierarchy_provider_as_master_key_provider() {
        let hierarchy = Arc::new(KeyHierarchy::new("prod", StaticKeyProvider::new(key_a())));
        let provider = HierarchyProvider::new(hierarchy);
        let key = provider.get_master_key().await.unwrap();
        assert_eq!(key.as_bytes(), key_a().as_bytes());
    }
}
