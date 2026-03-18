//! # Enkastela
//!
//! Application-level field encryption for PostgreSQL.
//! Written in Rust. Built for production.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use enkastela::Vault;
//!
//! # async fn example() -> Result<(), enkastela::Error> {
//! let vault = Vault::builder()
//!     .database_url("postgres://localhost/mydb?sslmode=require")
//!     .master_key_from_env("ENKASTELA_MASTER_KEY")
//!     .run_migrations()
//!     .build()
//!     .await?;
//!
//! let ciphertext = vault.encrypt_field("users", "email", b"alice@example.com").await?;
//! let plaintext = vault.decrypt_field("users", "email", &ciphertext).await?;
//! assert_eq!(&*plaintext, b"alice@example.com");
//! # Ok(())
//! # }
//! ```

pub mod access;
pub mod audit;
pub mod blind;
pub mod compliance;
pub mod config;
pub mod crypto;
pub mod error;
pub mod firewall;
pub mod gdpr;
pub mod intrusion;
pub mod keyring;
pub mod observability;
pub mod rotation;
pub mod storage;
pub mod tenant;
pub mod types;
pub mod validation;
pub mod vault;

// Re-exports for public API
pub use config::EnkastelaConfig;
pub use crypto::secret::SecretKey;
pub use error::Error;
pub use keyring::provider::{EnvKeyProvider, MasterKeyProvider, StaticKeyProvider};
pub use types::traits::{EncryptionMode, FieldDef, VaultEncryptable};
pub use vault::{Vault, VaultBuilder};

#[cfg(feature = "kms-aws")]
pub use keyring::aws_kms::AwsKmsProvider;
#[cfg(feature = "kms-azure")]
pub use keyring::azure_kv::AzureKeyVaultProvider;
#[cfg(feature = "kms-gcp")]
pub use keyring::gcp_kms::GcpKmsProvider;
#[cfg(feature = "kms-hashicorp")]
pub use keyring::hashicorp::HashiCorpVaultProvider;
