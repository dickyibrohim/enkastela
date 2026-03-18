//! Master key provider trait and implementations.
//!
//! # Security
//!
//! In production, use a KMS (AWS KMS, GCP KMS, HashiCorp Vault)
//! or at minimum an environment variable. NEVER load keys from files
//! on disk in production.

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;
use crate::error::Error;

/// Trait for providing the master key.
///
/// Implement this trait to integrate with your key management system.
#[async_trait]
pub trait MasterKeyProvider: Send + Sync {
    /// Retrieves the master key.
    ///
    /// This is called once during [`crate::vault::Vault`] construction. The key is then
    /// used to derive all sub-keys via HKDF.
    async fn get_master_key(&self) -> Result<SecretKey, Error>;
}

/// Loads the master key from an environment variable (base64-encoded).
///
/// Suitable for development and simple deployments. For production,
/// consider using a KMS provider.
pub struct EnvKeyProvider {
    env_var: String,
}

impl EnvKeyProvider {
    /// Creates a provider that reads from the specified environment variable.
    ///
    /// The variable must contain a 32-byte key encoded as base64.
    pub fn new(env_var: &str) -> Self {
        Self {
            env_var: env_var.to_string(),
        }
    }
}

#[async_trait]
impl MasterKeyProvider for EnvKeyProvider {
    async fn get_master_key(&self) -> Result<SecretKey, Error> {
        let encoded = std::env::var(&self.env_var)
            .map_err(|_| Error::ProviderFailed("required environment variable not set".into()))?;

        let bytes = Zeroizing::new(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encoded)
                .map_err(|_| Error::ProviderFailed("master key is not valid base64".into()))?,
        );

        SecretKey::from_slice(&bytes)
            .ok_or_else(|| Error::ProviderFailed("master key must be exactly 32 bytes".into()))
    }
}

/// A static key provider for testing purposes only.
///
/// # Security
///
/// Do NOT use this in production. It holds the key in memory with no
/// access control or audit trail.
pub struct StaticKeyProvider {
    key: SecretKey,
}

impl StaticKeyProvider {
    /// Creates a provider with a fixed key. For testing only.
    pub fn new(key: SecretKey) -> Self {
        Self { key }
    }
}

#[async_trait]
impl MasterKeyProvider for StaticKeyProvider {
    async fn get_master_key(&self) -> Result<SecretKey, Error> {
        // We must return a new SecretKey (can't clone).
        // Copy the bytes to create a new instance.
        Ok(SecretKey::from_bytes(*self.key.as_bytes()))
    }
}
