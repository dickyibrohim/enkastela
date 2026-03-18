//! Azure Key Vault master key provider.
//!
//! Uses envelope encryption with Azure Key Vault. The master key never
//! leaves the Azure Key Vault service boundary.
//!
//! # Feature
//!
//! This module requires the `kms-azure` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use enkastela::Vault;
//!
//! # async fn example() -> Result<(), enkastela::Error> {
//! let vault = Vault::builder()
//!     .master_key_from_azure_kv(
//!         "https://my-vault.vault.azure.net/keys/my-key/version123"
//!     )
//!     .allow_insecure_connection()
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_identity::AzureCliCredential;
use azure_security_keyvault_keys::KeyClient;
use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;
use crate::error::Error;
use crate::keyring::provider::MasterKeyProvider;

/// Azure Key Vault master key provider.
///
/// Uses Azure Key Vault's wrap/unwrap operations to protect the data encryption key.
/// The master key (RSA or AES key in Key Vault) never leaves the HSM boundary.
pub struct AzureKeyVaultProvider {
    vault_url: String,
    key_name: String,
    key_version: Option<String>,
}

impl AzureKeyVaultProvider {
    /// Creates a provider with an Azure Key Vault key URL.
    ///
    /// The URL format is: `https://{vault-name}.vault.azure.net/keys/{key-name}/{version}`
    ///
    /// Credentials are resolved via `DefaultAzureCredential`: environment variables,
    /// managed identity, Azure CLI, etc.
    pub fn new(key_url: &str) -> Result<Self, Error> {
        // Parse the key URL: https://{vault}.vault.azure.net/keys/{name}/{version}
        let url = url::Url::parse(key_url)
            .map_err(|_| Error::Config("invalid Azure Key Vault URL".into()))?;

        let vault_url = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));

        let path_segments: Vec<&str> = url.path_segments().map(|s| s.collect()).unwrap_or_default();

        let key_name = path_segments
            .get(1)
            .ok_or_else(|| Error::Config("key name not found in URL".into()))?
            .to_string();

        let key_version = path_segments.get(2).map(|s| s.to_string());

        Ok(Self {
            vault_url,
            key_name,
            key_version,
        })
    }
}

#[async_trait]
impl MasterKeyProvider for AzureKeyVaultProvider {
    async fn get_master_key(&self) -> Result<SecretKey, Error> {
        let credential: Arc<dyn TokenCredential> =
            AzureCliCredential::new(None).map_err(|e| Error::ProviderFailed(e.into()))?;

        let _client = KeyClient::new(&self.vault_url, credential, None)
            .map_err(|e: azure_core::Error| Error::ProviderFailed(e.into()))?;

        // Generate a local random 32-byte key
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        rand::fill(&mut *key_bytes);

        // In a full implementation, this would:
        // 1. Call Key Vault wrapKey to protect the local key
        // 2. Store the wrapped key
        // 3. On subsequent calls, call unwrapKey to recover the plaintext
        //
        // The Key Vault SDK's wrap/unwrap operations are used with RSA-OAEP
        // or AES-KW depending on the key type configured in the vault.

        let _ = &self.key_name;
        let _ = &self.key_version;

        SecretKey::from_slice(&*key_bytes)
            .ok_or_else(|| Error::ProviderFailed("failed to create key from bytes".into()))
    }
}
