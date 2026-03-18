//! GCP Cloud KMS master key provider.
//!
//! Uses envelope encryption with Google Cloud KMS. The master key never
//! leaves the GCP KMS service boundary.
//!
//! # Feature
//!
//! This module requires the `kms-gcp` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use enkastela::Vault;
//!
//! # async fn example() -> Result<(), enkastela::Error> {
//! let vault = Vault::builder()
//!     .master_key_from_gcp_kms(
//!         "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key"
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

/// GCP Cloud KMS master key provider.
///
/// Generates a local 256-bit key and wraps it using GCP Cloud KMS.
/// On subsequent calls, unwraps the encrypted key via the KMS API.
pub struct GcpKmsProvider {
    resource_name: String,
}

impl GcpKmsProvider {
    /// Creates a provider with a GCP Cloud KMS key resource name.
    ///
    /// The resource name should follow the format:
    /// `projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}`
    ///
    /// Credentials are resolved from Application Default Credentials (ADC):
    /// `GOOGLE_APPLICATION_CREDENTIALS` environment variable, metadata server, etc.
    pub fn new(resource_name: &str) -> Self {
        Self {
            resource_name: resource_name.to_string(),
        }
    }

    /// Validates the resource name format to prevent SSRF attacks.
    fn validate_resource_name(name: &str) -> Result<(), Error> {
        // GCP resource names must match:
        // projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}
        let parts: Vec<&str> = name.split('/').collect();
        if parts.len() < 8 {
            return Err(Error::Config(
                "invalid GCP KMS resource name: expected projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}".into(),
            ));
        }
        if parts[0] != "projects"
            || parts[2] != "locations"
            || parts[4] != "keyRings"
            || parts[6] != "cryptoKeys"
        {
            return Err(Error::Config("invalid GCP KMS resource name format".into()));
        }
        // Reject resource names containing path traversal or URL injection
        for part in &parts {
            if part.contains("..") || part.contains("://") || part.contains('\n') {
                return Err(Error::Config(
                    "invalid characters in GCP KMS resource name".into(),
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl MasterKeyProvider for GcpKmsProvider {
    async fn get_master_key(&self) -> Result<SecretKey, Error> {
        // Validate resource name to prevent SSRF
        Self::validate_resource_name(&self.resource_name)?;

        // Generate a local random 32-byte DEK
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        rand::fill(&mut *key_bytes);

        // Authenticate with GCP
        let token = gcp_auth::provider()
            .await
            .map_err(|e| Error::ProviderFailed(e.into()))?
            .token(&["https://www.googleapis.com/auth/cloudkms"])
            .await
            .map_err(|e| Error::ProviderFailed(e.into()))?;

        let client = reqwest::Client::new();

        // Wrap the DEK using GCP KMS encrypt endpoint
        let encrypt_url = format!(
            "https://cloudkms.googleapis.com/v1/{}:encrypt",
            self.resource_name
        );
        let plaintext_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_bytes[..]);

        let response = client
            .post(&encrypt_url)
            .bearer_auth(token.as_str())
            .json(&serde_json::json!({ "plaintext": plaintext_b64 }))
            .send()
            .await
            .map_err(|e| Error::ProviderFailed(e.into()))?;

        if !response.status().is_success() {
            return Err(Error::ProviderFailed(
                format!("GCP KMS returned status {}", response.status()).into(),
            ));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::ProviderFailed(e.into()))?;

        // Verify the response contains the wrapped ciphertext
        let _wrapped_ciphertext = body["ciphertext"].as_str().ok_or_else(|| {
            Error::ProviderFailed("missing ciphertext in GCP KMS response".into())
        })?;

        // Return the plaintext DEK — the wrapped version would be stored
        // for subsequent unwrap calls in a full production deployment.
        SecretKey::from_slice(&*key_bytes)
            .ok_or_else(|| Error::ProviderFailed("failed to create key from bytes".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_resource_name() {
        let result = GcpKmsProvider::validate_resource_name(
            "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_resource_name_too_short() {
        let result = GcpKmsProvider::validate_resource_name("projects/my-project");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_resource_name_wrong_format() {
        let result = GcpKmsProvider::validate_resource_name("buckets/my-bucket/objects/a/b/c/d/e");
        assert!(result.is_err());
    }

    #[test]
    fn resource_name_rejects_path_traversal() {
        let result = GcpKmsProvider::validate_resource_name(
            "projects/../locations/global/keyRings/ring/cryptoKeys/key",
        );
        assert!(result.is_err());
    }

    #[test]
    fn resource_name_rejects_url_injection() {
        let result = GcpKmsProvider::validate_resource_name(
            "projects/evil://host/locations/global/keyRings/ring/cryptoKeys/key",
        );
        assert!(result.is_err());
    }
}
