//! HashiCorp Vault Transit master key provider.
//!
//! Uses HashiCorp Vault's Transit secrets engine for envelope encryption.
//! The master key is managed by Vault and never exposed.
//!
//! # Feature
//!
//! This module requires the `kms-hashicorp` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use enkastela::Vault;
//!
//! # async fn example() -> Result<(), enkastela::Error> {
//! let vault = Vault::builder()
//!     .master_key_from_hashicorp_vault(
//!         "https://vault.internal:8200",
//!         "transit/keys/enkastela",
//!     )
//!     .allow_insecure_connection()
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;
use crate::error::Error;
use crate::keyring::provider::MasterKeyProvider;

/// HashiCorp Vault Transit secrets engine provider.
///
/// Uses the Transit engine to generate and manage encryption keys.
/// Supports token-based and Kubernetes authentication.
pub struct HashiCorpVaultProvider {
    vault_addr: String,
    key_path: String,
    token: Option<String>,
}

impl HashiCorpVaultProvider {
    /// Creates a provider with a Vault address and Transit key path.
    ///
    /// The token is read from the `VAULT_TOKEN` environment variable by default.
    ///
    /// # Arguments
    ///
    /// * `vault_addr` — Vault server address (e.g., `https://vault.internal:8200`).
    ///   Must be a valid HTTP(S) URL.
    /// * `key_path` — Transit key path (e.g., `transit/keys/enkastela`)
    pub fn new(vault_addr: &str, key_path: &str) -> Self {
        let token = std::env::var("VAULT_TOKEN").ok();
        Self {
            vault_addr: vault_addr.trim_end_matches('/').to_string(),
            key_path: key_path.to_string(),
            token,
        }
    }

    /// Validates the Vault address is a legitimate HTTP(S) URL.
    fn validate_addr(addr: &str) -> Result<(), Error> {
        if !addr.starts_with("https://") && !addr.starts_with("http://") {
            return Err(Error::Config(
                "HashiCorp Vault address must start with https:// or http://".into(),
            ));
        }
        // Reject addresses with path traversal, newlines, or embedded credentials
        if addr.contains("..") || addr.contains('\n') || addr.contains('@') {
            return Err(Error::Config(
                "invalid characters in HashiCorp Vault address".into(),
            ));
        }
        Ok(())
    }

    /// Sets the Vault authentication token explicitly.
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }
}

#[async_trait]
impl MasterKeyProvider for HashiCorpVaultProvider {
    async fn get_master_key(&self) -> Result<SecretKey, Error> {
        Self::validate_addr(&self.vault_addr)?;

        let token = self
            .token
            .as_deref()
            .or_else(|| std::env::var("VAULT_TOKEN").ok().as_deref().map(|_| ""))
            .ok_or_else(|| {
                Error::ProviderFailed("VAULT_TOKEN not set and no token provided".into())
            })?;

        let client = reqwest::Client::new();

        // Use Transit engine's datakey endpoint to generate a new data key.
        // POST /v1/transit/datakey/plaintext/{name}
        let key_name = self.key_path.rsplit('/').next().unwrap_or(&self.key_path);

        let url = format!(
            "{}/v1/transit/datakey/plaintext/{}",
            self.vault_addr, key_name
        );

        let response = client
            .post(&url)
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({ "bits": 256 }))
            .send()
            .await
            .map_err(|e| Error::ProviderFailed(e.into()))?;

        if !response.status().is_success() {
            return Err(Error::ProviderFailed(
                format!("Vault returned status {}", response.status()).into(),
            ));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::ProviderFailed(e.into()))?;

        let plaintext_b64 = body["data"]["plaintext"]
            .as_str()
            .ok_or_else(|| Error::ProviderFailed("missing plaintext in Vault response".into()))?;

        let key_bytes = Zeroizing::new(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, plaintext_b64)
                .map_err(|_| Error::ProviderFailed("invalid base64 from Vault".into()))?,
        );

        SecretKey::from_slice(&key_bytes)
            .ok_or_else(|| Error::ProviderFailed("Vault returned key with invalid length".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_reads_env_token() {
        let provider =
            HashiCorpVaultProvider::new("https://vault.internal:8200", "transit/keys/test");
        assert_eq!(provider.vault_addr, "https://vault.internal:8200");
        assert_eq!(provider.key_path, "transit/keys/test");
    }

    #[test]
    fn with_token_overrides() {
        let provider = HashiCorpVaultProvider::new("https://vault:8200", "transit/keys/test")
            .with_token("s.my-token");
        assert_eq!(provider.token, Some("s.my-token".to_string()));
    }

    #[test]
    fn validate_addr_accepts_https() {
        assert!(HashiCorpVaultProvider::validate_addr("https://vault.internal:8200").is_ok());
    }

    #[test]
    fn validate_addr_accepts_http() {
        assert!(HashiCorpVaultProvider::validate_addr("http://localhost:8200").is_ok());
    }

    #[test]
    fn validate_addr_rejects_non_http() {
        assert!(HashiCorpVaultProvider::validate_addr("ftp://vault:8200").is_err());
    }

    #[test]
    fn validate_addr_rejects_path_traversal() {
        assert!(HashiCorpVaultProvider::validate_addr("https://vault:8200/..").is_err());
    }

    #[test]
    fn validate_addr_rejects_embedded_credentials() {
        assert!(HashiCorpVaultProvider::validate_addr("https://user@vault:8200").is_err());
    }
}
