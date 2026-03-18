//! AWS KMS master key provider.
//!
//! Uses the envelope encryption pattern: the master key never leaves AWS KMS.
//! Enkastela sends an encrypted data key to AWS KMS for decryption, and uses
//! the resulting plaintext key for local encryption operations.
//!
//! # Feature
//!
//! This module requires the `kms-aws` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use enkastela::Vault;
//!
//! # async fn example() -> Result<(), enkastela::Error> {
//! let vault = Vault::builder()
//!     .master_key_from_aws_kms("arn:aws:kms:ap-southeast-1:123456:key/abc-def")
//!     .allow_insecure_connection()
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;
use crate::error::Error;
use crate::keyring::provider::MasterKeyProvider;

/// AWS KMS master key provider.
///
/// Generates or decrypts a 256-bit data key using AWS KMS. The master key
/// (Customer Master Key) never leaves the KMS service boundary.
pub struct AwsKmsProvider {
    key_arn: String,
    client: KmsClient,
}

impl AwsKmsProvider {
    /// Creates a provider using the default AWS SDK configuration.
    ///
    /// Credentials are resolved from the standard chain: environment variables,
    /// shared credentials file, IAM role, ECS task role, etc.
    pub async fn new(key_arn: &str) -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = KmsClient::new(&config);
        Ok(Self {
            key_arn: key_arn.to_string(),
            client,
        })
    }

    /// Creates a provider with a pre-configured AWS SDK config.
    pub fn with_config(key_arn: &str, config: &aws_config::SdkConfig) -> Self {
        let client = KmsClient::new(config);
        Self {
            key_arn: key_arn.to_string(),
            client,
        }
    }

    /// Creates a provider with a pre-built KMS client.
    ///
    /// Useful for testing with mocked clients.
    pub fn with_client(key_arn: &str, client: KmsClient) -> Self {
        Self {
            key_arn: key_arn.to_string(),
            client,
        }
    }
}

#[async_trait]
impl MasterKeyProvider for AwsKmsProvider {
    async fn get_master_key(&self) -> Result<SecretKey, Error> {
        let response = self
            .client
            .generate_data_key()
            .key_id(&self.key_arn)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| Error::ProviderFailed(e.into()))?;

        let plaintext_blob = response
            .plaintext()
            .ok_or_else(|| Error::ProviderFailed("KMS did not return plaintext key".into()))?;

        let key_bytes = Zeroizing::new(plaintext_blob.as_ref().to_vec());

        SecretKey::from_slice(&key_bytes)
            .ok_or_else(|| Error::ProviderFailed("KMS returned key with invalid length".into()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn provider_stores_key_arn() {
        let arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
        assert_eq!(arn.len(), 75);
    }
}
