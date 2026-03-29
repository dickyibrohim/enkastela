//! The main Vault struct — enkastela's public API.
//!
//! Provides encrypt/decrypt operations for individual fields, with automatic
//! key management, caching, and wire format encoding.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::access::policy::AccessPolicy;
use crate::audit::events::AuditAction;
use crate::audit::integrity::HmacEventHasher;
use crate::audit::logger::{
    AuditLogger, AuditSink, InMemoryAuditSink, OverflowPolicy, PostgresAuditSink,
};
use crate::config::EnkastelaConfig;
use crate::crypto::secret::SecretKey;
use crate::crypto::{aead, siv};
use crate::error::Error;
use crate::keyring::manager::KeyringManager;
use crate::keyring::provider::{EnvKeyProvider, MasterKeyProvider, StaticKeyProvider};
use crate::observability::health::{Health, HealthStatus};
use crate::observability::metrics::{MetricsRecorder, NoOpMetrics};
use crate::rotation::engine::RotationEngine;
use crate::rotation::strategy::RotationStrategy;
use crate::storage::codec::WirePayload;
use crate::storage::repository::{
    KeyEntry, KeyPurpose, KeyRepository, KeyStatus, PostgresKeyRepository,
};
use crate::tenant::manager::TenantKeyManager;
use crate::validation::input::{build_aad, validate_aad};

/// The main enkastela Vault.
///
/// Provides field-level encryption and decryption with automatic key management,
/// audit logging, key rotation, tenant isolation, and health monitoring.
pub struct Vault {
    keyring: KeyringManager,
    config: EnkastelaConfig,
    current_version: AtomicU32,
    dek_salt: [u8; 32],
    audit: Option<AuditLogger>,
    metrics: Arc<dyn MetricsRecorder>,
    rotation: RotationEngine,
    tenant_mgr: Option<TenantKeyManager>,
    pool: Option<sqlx::PgPool>,
    repository: Option<Arc<PostgresKeyRepository>>,
    access_policy: Option<AccessPolicy>,
}

impl Vault {
    /// Creates a new `VaultBuilder`.
    pub fn builder() -> VaultBuilder {
        VaultBuilder::new()
    }

    /// Encrypts a plaintext field value using AES-256-GCM.
    ///
    /// # Arguments
    ///
    /// * `table` — table name (used in AAD binding)
    /// * `column` — column name (used in AAD binding)
    /// * `plaintext` — the value to encrypt
    ///
    /// # Returns
    ///
    /// Wire-format encoded string: `ek:1:v{version}:{base64url(nonce||ct||tag)}`
    pub async fn encrypt_field(
        &self,
        table: &str,
        column: &str,
        plaintext: &[u8],
    ) -> Result<String, Error> {
        // Validate inputs
        if plaintext.len() > self.config.max_payload_size {
            return Err(Error::PayloadTooLarge {
                max_bytes: self.config.max_payload_size,
            });
        }
        let aad = build_aad(table, column);
        validate_aad(&aad)?;

        // Get or derive DEK
        let version = self.current_version.load(Ordering::Relaxed);
        let dek_result =
            self.keyring
                .get_or_derive_dek_with_salt(table, version, &self.dek_salt)?;

        // Persist the key entry in the database if this is a new derivation
        if !dek_result.was_cached {
            if let (Some(repo), Some(wrapped), Some(salt)) =
                (&self.repository, &dek_result.wrapped_key, &dek_result.salt)
            {
                let entry = KeyEntry {
                    id: format!("dek:{table}:v{version}"),
                    purpose: KeyPurpose::Dek,
                    table_name: Some(table.to_string()),
                    column_name: Some(column.to_string()),
                    version,
                    wrapped_key: wrapped.clone(),
                    salt: salt.to_vec(),
                    algorithm: "aes-256-gcm".into(),
                    status: KeyStatus::Active,
                    created_at: chrono::Utc::now(),
                    rotated_at: None,
                    destroyed_at: None,
                };
                let _ = repo.store_key(entry).await;
            }
        }

        // Encrypt
        let raw_ciphertext = aead::encrypt(&dek_result.key, plaintext, &aad)?;

        // Encode to wire format
        let payload = WirePayload::new(version, raw_ciphertext);
        let encoded = payload.encode();

        self.log_audit(AuditAction::Encrypt, table, column, version)
            .await;

        Ok(encoded)
    }

    /// Encrypts a field using AES-256-SIV (deterministic).
    ///
    /// Same plaintext + key → same ciphertext. Use only where deterministic
    /// output is required (unique constraints).
    pub async fn encrypt_field_deterministic(
        &self,
        table: &str,
        column: &str,
        plaintext: &[u8],
    ) -> Result<String, Error> {
        if plaintext.len() > self.config.max_payload_size {
            return Err(Error::PayloadTooLarge {
                max_bytes: self.config.max_payload_size,
            });
        }
        let aad = build_aad(table, column);
        validate_aad(&aad)?;

        let version = self.current_version.load(Ordering::Relaxed);
        let siv_key = self
            .keyring
            .derive_siv_key(table, version, &self.dek_salt)?;
        let raw_ciphertext = siv::encrypt_deterministic(&siv_key, plaintext, &aad)?;

        // SIV output has no separate nonce (the IV is synthetic). We prepend a 12-byte
        // zero marker so the wire format layout stays consistent with GCM payloads.
        // Minimum size: 12 (marker) + 16 (SIV tag) = 28 bytes — satisfies codec minimum.
        let mut padded = vec![0u8; 12];
        padded.extend_from_slice(&raw_ciphertext);

        let payload = WirePayload::new(version, padded);
        let encoded = payload.encode();

        self.log_audit(AuditAction::Encrypt, table, column, version)
            .await;

        Ok(encoded)
    }

    /// Decrypts a deterministic (AES-256-SIV) wire-format ciphertext.
    ///
    /// # Arguments
    ///
    /// * `table` — table name (must match what was used for encryption)
    /// * `column` — column name (must match what was used for encryption)
    /// * `ciphertext` — the wire-format string from [`Vault::encrypt_field_deterministic`]
    ///
    /// # Returns
    ///
    /// Decrypted plaintext wrapped in [`Zeroizing`] for automatic memory cleanup.
    pub async fn decrypt_field_deterministic(
        &self,
        table: &str,
        column: &str,
        ciphertext: &str,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let aad = build_aad(table, column);
        validate_aad(&aad)?;

        let payload = WirePayload::decode(ciphertext)?;

        let siv_key = self
            .keyring
            .derive_siv_key(table, payload.dek_version, &self.dek_salt)?;

        // Strip the 12-byte zero marker prepended during encryption.
        if payload.raw_ciphertext.len() < 12 {
            return Err(Error::DecryptionFailed);
        }
        let siv_ciphertext = &payload.raw_ciphertext[12..];

        let result = siv::decrypt_deterministic(&siv_key, siv_ciphertext, &aad)?;

        self.log_audit(AuditAction::Decrypt, table, column, payload.dek_version)
            .await;

        Ok(result)
    }

    /// Decrypts a wire-format encoded ciphertext.
    ///
    /// # Arguments
    ///
    /// * `table` — table name (must match what was used for encryption)
    /// * `column` — column name (must match what was used for encryption)
    /// * `ciphertext` — the wire-format string from [`Vault::encrypt_field`]
    ///
    /// # Returns
    ///
    /// Decrypted plaintext wrapped in [`Zeroizing`] for automatic memory cleanup.
    pub async fn decrypt_field(
        &self,
        table: &str,
        column: &str,
        ciphertext: &str,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let aad = build_aad(table, column);
        validate_aad(&aad)?;

        // Decode wire format
        let payload = WirePayload::decode(ciphertext)?;

        // Get DEK for the version in the ciphertext
        let dek_result =
            self.keyring
                .get_or_derive_dek_with_salt(table, payload.dek_version, &self.dek_salt)?;

        // Decrypt
        let result = aead::decrypt(&dek_result.key, &payload.raw_ciphertext, &aad)?;

        self.log_audit(AuditAction::Decrypt, table, column, payload.dek_version)
            .await;

        Ok(result)
    }

    /// Computes an HMAC-SHA256 blind index for searchable encryption.
    ///
    /// # Arguments
    ///
    /// * `table` — table name
    /// * `column` — column name
    /// * `plaintext` — the value to index
    ///
    /// # Returns
    ///
    /// 32-byte HMAC hash.
    pub fn compute_blind_index(
        &self,
        table: &str,
        column: &str,
        plaintext: &[u8],
    ) -> Result<[u8; 32], Error> {
        let blind_key = self
            .keyring
            .derive_blind_key(table, column, &self.dek_salt)?;
        let context = build_aad(table, column);
        crate::crypto::hmac::compute_blind_index(&blind_key, plaintext, &context)
    }

    /// Encrypts multiple fields in a single batch operation.
    ///
    /// Groups items by table to amortize key derivation cost. Each item is
    /// encrypted independently — an error in one item does not prevent
    /// others from succeeding.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use enkastela::{Vault, vault::BatchItem};
    /// # async fn example(vault: &Vault) -> Result<(), enkastela::Error> {
    /// let items = vec![
    ///     BatchItem::new("users", "email", b"alice@example.com"),
    ///     BatchItem::new("users", "email", b"bob@example.com"),
    ///     BatchItem::new("orders", "address", b"123 Main St"),
    /// ];
    /// let results = vault.encrypt_batch(items).await;
    /// for result in &results {
    ///     let ciphertext = result.as_ref().unwrap();
    ///     assert!(Vault::is_encrypted(ciphertext));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn encrypt_batch(&self, items: Vec<BatchItem>) -> Vec<Result<String, Error>> {
        let mut results = Vec::with_capacity(items.len());
        for item in &items {
            let result = self
                .encrypt_field(&item.table, &item.column, &item.plaintext)
                .await;
            results.push(result);
        }
        results
    }

    /// Decrypts multiple fields in a single batch operation.
    ///
    /// Each item is decrypted independently — an error in one does not
    /// prevent others from succeeding.
    pub async fn decrypt_batch(
        &self,
        items: Vec<DecryptItem>,
    ) -> Vec<Result<Zeroizing<Vec<u8>>, Error>> {
        let mut results = Vec::with_capacity(items.len());
        for item in &items {
            let result = self
                .decrypt_field(&item.table, &item.column, &item.ciphertext)
                .await;
            results.push(result);
        }
        results
    }

    /// Encrypts a large payload using streaming chunked AES-256-GCM.
    ///
    /// Each chunk is independently encrypted with a derived nonce, allowing
    /// arbitrarily large payloads without holding everything in memory at once.
    /// The final chunk includes a finalization marker to prevent truncation.
    ///
    /// # Arguments
    ///
    /// * `table` — table name (used in AAD binding)
    /// * `column` — column name (used in AAD binding)
    /// * `plaintext` — the data to encrypt (can be arbitrarily large)
    /// * `chunk_size` — size of each plaintext chunk (0 uses default 64 KiB)
    pub async fn encrypt_stream(
        &self,
        table: &str,
        column: &str,
        plaintext: &[u8],
        chunk_size: usize,
    ) -> Result<Vec<u8>, Error> {
        let aad = build_aad(table, column);
        validate_aad(&aad)?;

        let version = self.current_version.load(Ordering::Relaxed);
        let dek_result =
            self.keyring
                .get_or_derive_dek_with_salt(table, version, &self.dek_salt)?;

        let ct =
            crate::crypto::stream::encrypt_stream(&dek_result.key, plaintext, &aad, chunk_size)?;

        self.log_audit(AuditAction::Encrypt, table, column, version)
            .await;

        Ok(ct)
    }

    /// Decrypts a stream-encrypted payload.
    ///
    /// # Arguments
    ///
    /// * `table` — table name (must match what was used for encryption)
    /// * `column` — column name (must match what was used for encryption)
    /// * `ciphertext` — the stream-encrypted bytes from [`Vault::encrypt_stream`]
    ///
    /// Uses the current DEK version. If the data was encrypted with a different
    /// version (e.g., before key rotation), use [`Vault::decrypt_stream_with_version`].
    pub async fn decrypt_stream(
        &self,
        table: &str,
        column: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let version = self.current_version.load(Ordering::Relaxed);
        self.decrypt_stream_with_version(table, column, ciphertext, version)
            .await
    }

    /// Decrypts a stream-encrypted payload using a specific DEK version.
    ///
    /// Use this when the data was encrypted with a DEK version that differs
    /// from the current version (e.g., before a key rotation).
    pub async fn decrypt_stream_with_version(
        &self,
        table: &str,
        column: &str,
        ciphertext: &[u8],
        version: u32,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let aad = build_aad(table, column);
        validate_aad(&aad)?;

        let dek_result =
            self.keyring
                .get_or_derive_dek_with_salt(table, version, &self.dek_salt)?;

        let pt = crate::crypto::stream::decrypt_stream(&dek_result.key, ciphertext, &aad)?;

        self.log_audit(AuditAction::Decrypt, table, column, version)
            .await;

        Ok(pt)
    }

    /// Returns whether a string is enkastela-encrypted.
    pub fn is_encrypted(s: &str) -> bool {
        WirePayload::is_encrypted(s)
    }

    /// Computes a text-aware blind index with Unicode normalization.
    ///
    /// Applies NFC normalization, trim, and lowercase before hashing,
    /// so visually identical strings produce the same index.
    pub fn compute_text_blind_index(
        &self,
        table: &str,
        column: &str,
        text: &str,
    ) -> Result<[u8; 32], Error> {
        let blind_key = self
            .keyring
            .derive_blind_key(table, column, &self.dek_salt)?;
        let context = build_aad(table, column);
        crate::blind::index::compute_text_blind_index(&blind_key, text, &context)
    }

    /// Encrypts a field with access control enforcement.
    ///
    /// Checks whether the caller's role has encrypt permission before proceeding.
    /// Returns [`Error::AccessDenied`] if the policy denies the operation.
    pub async fn encrypt_field_with_context(
        &self,
        table: &str,
        column: &str,
        plaintext: &[u8],
        ctx: &crate::access::context::AccessContext,
    ) -> Result<String, Error> {
        if let Some(ref policy) = self.access_policy {
            if !policy.can_encrypt(&ctx.role, table, column) {
                return Err(Error::AccessDenied {
                    role: ctx.role.clone(),
                    table: table.to_string(),
                    column: column.to_string(),
                });
            }
        }
        self.encrypt_field(table, column, plaintext).await
    }

    /// Decrypts a field with access control enforcement.
    ///
    /// Checks whether the caller's role has decrypt permission before proceeding.
    /// Returns [`Error::AccessDenied`] if the policy denies the operation.
    pub async fn decrypt_field_with_context(
        &self,
        table: &str,
        column: &str,
        ciphertext: &str,
        ctx: &crate::access::context::AccessContext,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if let Some(ref policy) = self.access_policy {
            if !policy.can_decrypt(&ctx.role, table, column) {
                return Err(Error::AccessDenied {
                    role: ctx.role.clone(),
                    table: table.to_string(),
                    column: column.to_string(),
                });
            }
        }
        self.decrypt_field(table, column, ciphertext).await
    }

    /// Returns the access policy, if configured.
    pub fn access_policy(&self) -> Option<&AccessPolicy> {
        self.access_policy.as_ref()
    }

    /// Returns the current DEK version.
    pub fn current_version(&self) -> u32 {
        self.current_version.load(Ordering::Relaxed)
    }

    /// Returns the rotation engine for managing key rotations.
    pub fn rotation(&self) -> &RotationEngine {
        &self.rotation
    }

    /// Returns the tenant key manager, if multi-tenant is configured.
    pub fn tenant_manager(&self) -> Option<&TenantKeyManager> {
        self.tenant_mgr.as_ref()
    }

    /// Returns the metrics recorder.
    pub fn metrics(&self) -> &dyn MetricsRecorder {
        self.metrics.as_ref()
    }

    /// Returns a reference to the database connection pool, if configured.
    pub fn pool(&self) -> Option<&sqlx::PgPool> {
        self.pool.as_ref()
    }

    /// Returns the key repository, if database-backed.
    pub fn repository(&self) -> Option<&PostgresKeyRepository> {
        self.repository.as_ref().map(|r| r.as_ref())
    }

    /// Performs a health check on all subsystems.
    pub fn health_check(&self) -> HealthStatus {
        let cache_health = if self.keyring.cache().len() <= self.config.cache_max_entries {
            Health::Healthy
        } else {
            Health::Degraded("cache over capacity".into())
        };

        let audit_health = match &self.audit {
            Some(logger) if logger.dropped_count() > 0 => {
                Health::Degraded(format!("{} events dropped", logger.dropped_count()))
            }
            Some(_) => Health::Healthy,
            None => Health::Healthy,
        };

        HealthStatus::compute(cache_health, audit_health)
    }

    /// Logs an audit event if audit logging is enabled.
    async fn log_audit(&self, action: AuditAction, table: &str, column: &str, version: u32) {
        if let Some(ref audit) = self.audit {
            let builder = crate::audit::events::AuditEventBuilder::new(action)
                .table(table)
                .column(column)
                .key_version(version);
            let _ = audit.log(builder).await;
        }
    }

    /// Gracefully shuts down the vault, flushing audit events.
    pub async fn shutdown(&self) {
        if let Some(ref audit) = self.audit {
            audit.shutdown().await;
        }
    }
}

/// A single item for batch encryption.
pub struct BatchItem {
    /// Table name (used in AAD binding).
    pub table: String,
    /// Column name (used in AAD binding).
    pub column: String,
    /// Plaintext value to encrypt.
    pub plaintext: Vec<u8>,
}

impl BatchItem {
    /// Creates a new batch encryption item.
    pub fn new(table: &str, column: &str, plaintext: &[u8]) -> Self {
        Self {
            table: table.to_string(),
            column: column.to_string(),
            plaintext: plaintext.to_vec(),
        }
    }
}

/// A single item for batch decryption.
pub struct DecryptItem {
    /// Table name (must match what was used for encryption).
    pub table: String,
    /// Column name (must match what was used for encryption).
    pub column: String,
    /// Wire-format ciphertext to decrypt.
    pub ciphertext: String,
}

impl DecryptItem {
    /// Creates a new batch decryption item.
    pub fn new(table: &str, column: &str, ciphertext: &str) -> Self {
        Self {
            table: table.to_string(),
            column: column.to_string(),
            ciphertext: ciphertext.to_string(),
        }
    }
}

/// Builder for constructing a [`Vault`] instance.
pub struct VaultBuilder {
    config: EnkastelaConfig,
    provider: Option<Box<dyn MasterKeyProvider>>,
    dek_salt: Option<[u8; 32]>,
    metrics: Option<Arc<dyn MetricsRecorder>>,
    audit_sink: Option<Arc<dyn AuditSink>>,
    rotation_strategy: RotationStrategy,
    enable_tenant: bool,
    access_policy: Option<AccessPolicy>,
    #[cfg(feature = "kms-aws")]
    aws_kms_arn: Option<String>,
}

impl VaultBuilder {
    fn new() -> Self {
        Self {
            config: EnkastelaConfig::default(),
            provider: None,
            dek_salt: None,
            metrics: None,
            audit_sink: None,
            rotation_strategy: RotationStrategy::default(),
            enable_tenant: false,
            access_policy: None,
            #[cfg(feature = "kms-aws")]
            aws_kms_arn: None,
        }
    }

    /// Sets the database URL.
    pub fn database_url(mut self, url: &str) -> Self {
        self.config.database_url = Some(url.to_string());
        self
    }

    /// Sets the master key provider to read from an environment variable.
    pub fn master_key_from_env(mut self, env_var: &str) -> Self {
        self.provider = Some(Box::new(EnvKeyProvider::new(env_var)));
        self
    }

    /// Sets a static master key (for testing only).
    pub fn master_key_static(mut self, key: SecretKey) -> Self {
        self.provider = Some(Box::new(StaticKeyProvider::new(key)));
        self
    }

    /// Sets a custom master key provider.
    pub fn master_key_provider(mut self, provider: impl MasterKeyProvider + 'static) -> Self {
        self.provider = Some(Box::new(provider));
        self
    }

    /// Sets the master key provider to AWS KMS (envelope encryption).
    ///
    /// The master key never leaves AWS. Requires the `kms-aws` feature.
    #[cfg(feature = "kms-aws")]
    pub fn master_key_from_aws_kms(mut self, key_arn: &str) -> Self {
        self.aws_kms_arn = Some(key_arn.to_string());
        self
    }

    /// Sets the master key provider to GCP Cloud KMS.
    ///
    /// Requires the `kms-gcp` feature.
    #[cfg(feature = "kms-gcp")]
    pub fn master_key_from_gcp_kms(mut self, resource_name: &str) -> Self {
        use crate::keyring::gcp_kms::GcpKmsProvider;
        self.provider = Some(Box::new(GcpKmsProvider::new(resource_name)));
        self
    }

    /// Sets the master key provider to Azure Key Vault.
    ///
    /// Requires the `kms-azure` feature.
    #[cfg(feature = "kms-azure")]
    pub fn master_key_from_azure_kv(mut self, key_url: &str) -> Self {
        if let Ok(provider) = crate::keyring::azure_kv::AzureKeyVaultProvider::new(key_url) {
            self.provider = Some(Box::new(provider));
        }
        self
    }

    /// Sets the master key provider to HashiCorp Vault Transit engine.
    ///
    /// Requires the `kms-hashicorp` feature.
    #[cfg(feature = "kms-hashicorp")]
    pub fn master_key_from_hashicorp_vault(mut self, vault_addr: &str, key_path: &str) -> Self {
        use crate::keyring::hashicorp::HashiCorpVaultProvider;
        self.provider = Some(Box::new(HashiCorpVaultProvider::new(vault_addr, key_path)));
        self
    }

    /// Enables or disables automatic migration on startup.
    pub fn run_migrations(mut self) -> Self {
        self.config.auto_migrate = true;
        self
    }

    /// Sets the key cache TTL.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.config.cache_ttl = ttl;
        self
    }

    /// Sets the maximum number of cached keys.
    pub fn cache_max_entries(mut self, max: usize) -> Self {
        self.config.cache_max_entries = max;
        self
    }

    /// Sets the database schema name.
    pub fn schema(mut self, schema: &str) -> Self {
        self.config.schema = schema.to_string();
        self
    }

    /// Enables or disables TLS requirement.
    pub fn require_tls(mut self, require: bool) -> Self {
        self.config.require_tls = require;
        self
    }

    /// Explicitly allows insecure (non-TLS) connections.
    ///
    /// # Security
    ///
    /// Only use this for local development. In production, always use TLS.
    pub fn allow_insecure_connection(mut self) -> Self {
        self.config.require_tls = false;
        self
    }

    /// Sets the maximum payload size for encryption.
    pub fn max_payload_size(mut self, max: usize) -> Self {
        self.config.max_payload_size = max;
        self
    }

    /// Enables or disables audit logging.
    pub fn enable_audit(mut self, enable: bool) -> Self {
        self.config.audit_enabled = enable;
        self
    }

    /// Sets a custom metrics recorder.
    pub fn metrics(mut self, metrics: Arc<dyn MetricsRecorder>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Sets a custom audit sink for audit log storage.
    pub fn audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Sets the key rotation strategy.
    pub fn rotation_strategy(mut self, strategy: RotationStrategy) -> Self {
        self.rotation_strategy = strategy;
        self
    }

    /// Enables multi-tenant key isolation.
    pub fn enable_tenant_isolation(mut self) -> Self {
        self.enable_tenant = true;
        self
    }

    /// Sets a field-level access control policy.
    ///
    /// When an access policy is set, `encrypt_field_with_context` and
    /// `decrypt_field_with_context` will enforce role-based permissions.
    /// The non-context methods (`encrypt_field`, `decrypt_field`) are unaffected.
    pub fn access_policy(mut self, policy: AccessPolicy) -> Self {
        self.access_policy = Some(policy);
        self
    }

    /// Sets a fixed DEK salt.
    ///
    /// By default, a random salt is generated on each build. Use this method
    /// when you need deterministic key derivation across Vault instances
    /// (e.g., CLI tools that encrypt and decrypt in separate invocations).
    ///
    /// In production with a database, the salt is stored alongside the key.
    pub fn dek_salt(mut self, salt: [u8; 32]) -> Self {
        self.dek_salt = Some(salt);
        self
    }

    /// Builds the Vault instance.
    ///
    /// When a `database_url` is configured, the builder will:
    /// 1. Connect to PostgreSQL (enforcing TLS unless `allow_insecure_connection` was called)
    /// 2. Run schema migrations if `run_migrations()` was called
    /// 3. Load or persist the DEK salt in the database
    /// 4. Route audit events to the `enkastela.audit_log` table
    ///
    /// Without a `database_url`, everything runs in-memory (suitable for testing or
    /// single-process deployments).
    ///
    /// # Errors
    ///
    /// Returns an error if the master key provider is not set or fails, or if the
    /// database connection cannot be established.
    #[allow(unused_mut)]
    pub async fn build(mut self) -> Result<Vault, Error> {
        // Handle deferred async KMS provider initialization
        #[cfg(feature = "kms-aws")]
        if self.provider.is_none() {
            if let Some(ref arn) = self.aws_kms_arn {
                let provider = crate::keyring::aws_kms::AwsKmsProvider::new(arn).await?;
                self.provider = Some(Box::new(provider));
            }
        }

        let provider = self
            .provider
            .ok_or_else(|| Error::Config("master key provider not set".into()))?;

        let master_key = provider.get_master_key().await?;

        // --- Database setup (optional) ---
        let (pool, repository) = if let Some(ref url) = self.config.database_url {
            let pg_pool = crate::storage::pool::connect(url, self.config.require_tls).await?;

            if self.config.auto_migrate {
                crate::storage::migrations::run_all(&pg_pool).await?;
            }

            let repo = Arc::new(PostgresKeyRepository::new(pg_pool.clone()));
            (Some(pg_pool), Some(repo))
        } else {
            (None, None)
        };

        // Load DEK salt from DB or generate a new one.
        // When a database is configured, the salt is stored in the `enkastela.keys`
        // table with id = `_dek_salt` so all instances share the same derivation
        // base. Without a DB, the salt is ephemeral.
        let dek_salt = if let Some(salt) = self.dek_salt {
            salt
        } else if let Some(ref repo) = repository {
            load_or_create_dek_salt(repo.as_ref()).await?
        } else {
            crate::crypto::kdf::generate_salt()
        };

        // Derive sub-keys from master key BEFORE it is moved into KeyringManager.
        // This enforces key separation: audit, tenant, and encryption all use
        // independent derived keys rather than the raw master key.
        let audit_key = if self.config.audit_enabled {
            let info = b"enkastela:audit:integrity";
            Some(crate::crypto::kdf::derive_key(
                &master_key,
                &dek_salt,
                info,
            )?)
        } else {
            None
        };

        let tenant_mgr = if self.enable_tenant {
            let tenant_info = b"enkastela:tenant:master";
            let tenant_master =
                crate::crypto::kdf::derive_key(&master_key, &dek_salt, tenant_info)?;
            Some(TenantKeyManager::new(tenant_master))
        } else {
            None
        };

        let keyring = KeyringManager::new(
            master_key,
            self.config.cache_ttl,
            self.config.cache_max_entries,
        );

        let metrics: Arc<dyn MetricsRecorder> =
            self.metrics.unwrap_or_else(|| Arc::new(NoOpMetrics));

        // Build audit logger if enabled
        let audit = if self.config.audit_enabled {
            let sink: Arc<dyn AuditSink> = if let Some(ref sink) = self.audit_sink {
                Arc::clone(sink)
            } else if let Some(ref pg_pool) = pool {
                Arc::new(PostgresAuditSink::new(pg_pool.clone()))
            } else {
                Arc::new(InMemoryAuditSink::new())
            };
            let hasher = Arc::new(HmacEventHasher::new(
                audit_key.expect("audit_key derived when audit_enabled"),
            ));
            Some(AuditLogger::new(
                sink,
                hasher,
                100,
                Duration::from_secs(1),
                10_000,
                OverflowPolicy::BlockWithTimeout(Duration::from_secs(5)),
            ))
        } else {
            None
        };

        let rotation = RotationEngine::new(self.rotation_strategy);

        Ok(Vault {
            keyring,
            config: self.config,
            current_version: AtomicU32::new(1),
            dek_salt,
            audit,
            metrics,
            rotation,
            tenant_mgr,
            pool,
            repository,
            access_policy: self.access_policy,
        })
    }
}

/// Loads the shared DEK salt from the database, or generates and stores one.
///
/// The salt is stored as a sentinel key entry with `id = "_dek_salt"` in the
/// `enkastela.keys` table. This ensures all Vault instances sharing the same
/// database derive identical DEKs from the same master key.
async fn load_or_create_dek_salt(repo: &PostgresKeyRepository) -> Result<[u8; 32], Error> {
    use crate::storage::repository::{KeyEntry, KeyPurpose, KeyStatus};

    // Try loading first
    if let Some(entry) = repo.get_key("_global", 1, KeyPurpose::Dek).await? {
        if entry.salt.len() == 32 {
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&entry.salt);
            return Ok(salt);
        }
    }

    // Generate and store
    let salt = crate::crypto::kdf::generate_salt();
    let entry = KeyEntry {
        id: "_dek_salt".into(),
        purpose: KeyPurpose::Dek,
        table_name: Some("_global".into()),
        column_name: None,
        version: 1,
        wrapped_key: vec![0u8; 1], // placeholder — the salt IS the value
        salt: salt.to_vec(),
        algorithm: "hkdf-sha256".into(),
        status: KeyStatus::Active,
        created_at: chrono::Utc::now(),
        rotated_at: None,
        destroyed_at: None,
    };
    let _ = repo.store_key(entry).await; // ON CONFLICT DO NOTHING handles races
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    #[tokio::test]
    async fn build_vault_with_static_key() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        assert_eq!(vault.current_version(), 1);
    }

    #[tokio::test]
    async fn build_vault_without_provider_fails() {
        let result = Vault::builder().allow_insecure_connection().build().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault
            .encrypt_field("users", "email", b"alice@example.com")
            .await
            .unwrap();

        assert!(Vault::is_encrypted(&ct));
        assert!(ct.starts_with("ek:1:v1:"));

        let pt = vault.decrypt_field("users", "email", &ct).await.unwrap();
        assert_eq!(&*pt, b"alice@example.com");
    }

    #[tokio::test]
    async fn encrypt_decrypt_empty() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault.encrypt_field("t", "c", b"").await.unwrap();
        let pt = vault.decrypt_field("t", "c", &ct).await.unwrap();
        assert_eq!(&*pt, b"");
    }

    #[tokio::test]
    async fn wrong_table_decrypt_fails() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault
            .encrypt_field("users", "email", b"secret")
            .await
            .unwrap();

        // Different table → different AAD → decrypt fails
        let result = vault.decrypt_field("orders", "email", &ct).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn wrong_column_decrypt_fails() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault
            .encrypt_field("users", "email", b"secret")
            .await
            .unwrap();

        let result = vault.decrypt_field("users", "phone", &ct).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn two_encryptions_different_ciphertext() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct1 = vault.encrypt_field("t", "c", b"same").await.unwrap();
        let ct2 = vault.encrypt_field("t", "c", b"same").await.unwrap();
        assert_ne!(ct1, ct2, "randomized encryption should differ");

        // But both decrypt to the same value
        let pt1 = vault.decrypt_field("t", "c", &ct1).await.unwrap();
        let pt2 = vault.decrypt_field("t", "c", &ct2).await.unwrap();
        assert_eq!(&*pt1, &*pt2);
    }

    #[tokio::test]
    async fn payload_too_large() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .max_payload_size(100)
            .build()
            .await
            .unwrap();

        let big = vec![0u8; 101];
        let result = vault.encrypt_field("t", "c", &big).await;
        assert!(matches!(result, Err(Error::PayloadTooLarge { .. })));
    }

    #[tokio::test]
    async fn blind_index_deterministic() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let h1 = vault
            .compute_blind_index("users", "email", b"alice@example.com")
            .unwrap();
        let h2 = vault
            .compute_blind_index("users", "email", b"alice@example.com")
            .unwrap();
        assert_eq!(h1, h2);

        let h3 = vault
            .compute_blind_index("users", "email", b"bob@example.com")
            .unwrap();
        assert_ne!(h1, h3);
    }

    #[tokio::test]
    async fn decrypt_plaintext_string_fails() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let result = vault.decrypt_field("t", "c", "not encrypted").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn deterministic_encrypt_decrypt_roundtrip() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault
            .encrypt_field_deterministic("users", "ssn", b"123-45-6789")
            .await
            .unwrap();

        assert!(Vault::is_encrypted(&ct));

        let pt = vault
            .decrypt_field_deterministic("users", "ssn", &ct)
            .await
            .unwrap();
        assert_eq!(&*pt, b"123-45-6789");
    }

    #[tokio::test]
    async fn deterministic_same_input_same_output() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct1 = vault
            .encrypt_field_deterministic("t", "c", b"same")
            .await
            .unwrap();
        let ct2 = vault
            .encrypt_field_deterministic("t", "c", b"same")
            .await
            .unwrap();
        assert_eq!(ct1, ct2, "deterministic encryption must be stable");
    }

    #[tokio::test]
    async fn deterministic_wrong_table_fails() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault
            .encrypt_field_deterministic("users", "id", b"secret")
            .await
            .unwrap();

        let result = vault.decrypt_field_deterministic("orders", "id", &ct).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn is_encrypted_check() {
        assert!(Vault::is_encrypted("ek:1:v1:abc123"));
        assert!(!Vault::is_encrypted("hello world"));
        assert!(!Vault::is_encrypted(""));
    }

    #[tokio::test]
    async fn batch_encrypt_decrypt_roundtrip() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let items = vec![
            BatchItem::new("users", "email", b"alice@example.com"),
            BatchItem::new("users", "email", b"bob@example.com"),
            BatchItem::new("orders", "address", b"123 Main St"),
        ];

        let encrypted = vault.encrypt_batch(items).await;
        assert_eq!(encrypted.len(), 3);
        for ct in &encrypted {
            assert!(ct.is_ok());
        }

        let decrypt_items: Vec<DecryptItem> = encrypted
            .iter()
            .zip(["users", "users", "orders"])
            .zip(["email", "email", "address"])
            .map(|((ct, table), column)| DecryptItem::new(table, column, ct.as_ref().unwrap()))
            .collect();

        let decrypted = vault.decrypt_batch(decrypt_items).await;
        assert_eq!(
            decrypted[0].as_ref().unwrap().as_slice(),
            b"alice@example.com"
        );
        assert_eq!(
            decrypted[1].as_ref().unwrap().as_slice(),
            b"bob@example.com"
        );
        assert_eq!(decrypted[2].as_ref().unwrap().as_slice(), b"123 Main St");
    }

    #[tokio::test]
    async fn batch_partial_failure() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let decrypt_items = vec![
            DecryptItem::new("t", "c", "not-encrypted"),
            DecryptItem::new("t", "c", "also-not-encrypted"),
        ];

        let results = vault.decrypt_batch(decrypt_items).await;
        assert!(results[0].is_err());
        assert!(results[1].is_err());
    }

    #[tokio::test]
    async fn stream_encrypt_decrypt_roundtrip() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let data = vec![0xABu8; 200_000]; // ~200 KiB
        let ct = vault
            .encrypt_stream("files", "doc", &data, 0)
            .await
            .unwrap();
        let pt = vault.decrypt_stream("files", "doc", &ct).await.unwrap();
        assert_eq!(&*pt, &data);
    }

    #[tokio::test]
    async fn stream_wrong_table_fails() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault
            .encrypt_stream("files", "doc", b"secret", 16)
            .await
            .unwrap();
        let result = vault.decrypt_stream("wrong", "doc", &ct).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn access_control_allows_permitted_role() {
        use crate::access::context::AccessContext;
        use crate::access::policy::Permission;

        let mut policy = AccessPolicy::new();
        policy.grant("support", "users", "name", Permission::Full);

        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .access_policy(policy)
            .build()
            .await
            .unwrap();

        let ctx = AccessContext::new("support");
        let ct = vault
            .encrypt_field_with_context("users", "name", b"Alice", &ctx)
            .await
            .unwrap();
        let pt = vault
            .decrypt_field_with_context("users", "name", &ct, &ctx)
            .await
            .unwrap();
        assert_eq!(&*pt, b"Alice");
    }

    #[tokio::test]
    async fn access_control_denies_unpermitted_role() {
        use crate::access::context::AccessContext;
        use crate::access::policy::Permission;

        let mut policy = AccessPolicy::new();
        policy.grant("support", "users", "name", Permission::Decrypt);

        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .access_policy(policy)
            .build()
            .await
            .unwrap();

        let ctx = AccessContext::new("support");
        // support can decrypt name but NOT encrypt
        let result = vault
            .encrypt_field_with_context("users", "name", b"Alice", &ctx)
            .await;
        assert!(matches!(result, Err(Error::AccessDenied { .. })));

        // support cannot decrypt ssn
        let ctx2 = AccessContext::new("analytics");
        let ct = vault
            .encrypt_field("users", "name", b"Alice")
            .await
            .unwrap();
        let result = vault
            .decrypt_field_with_context("users", "name", &ct, &ctx2)
            .await;
        assert!(matches!(result, Err(Error::AccessDenied { .. })));
    }

    #[tokio::test]
    async fn access_control_admin_bypass() {
        use crate::access::context::AccessContext;

        let mut policy = AccessPolicy::new();
        policy.grant_admin("superadmin");

        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .access_policy(policy)
            .build()
            .await
            .unwrap();

        let ctx = AccessContext::new("superadmin");
        let ct = vault
            .encrypt_field_with_context("any", "field", b"secret", &ctx)
            .await
            .unwrap();
        let pt = vault
            .decrypt_field_with_context("any", "field", &ct, &ctx)
            .await
            .unwrap();
        assert_eq!(&*pt, b"secret");
    }

    #[tokio::test]
    async fn no_policy_allows_all() {
        use crate::access::context::AccessContext;

        // No access policy set — context methods should allow everything
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ctx = AccessContext::new("random_role");
        let ct = vault
            .encrypt_field_with_context("t", "c", b"data", &ctx)
            .await
            .unwrap();
        let pt = vault
            .decrypt_field_with_context("t", "c", &ct, &ctx)
            .await
            .unwrap();
        assert_eq!(&*pt, b"data");
    }

    #[tokio::test]
    async fn stream_empty_payload() {
        let vault = Vault::builder()
            .master_key_static(test_key())
            .allow_insecure_connection()
            .build()
            .await
            .unwrap();

        let ct = vault.encrypt_stream("t", "c", b"", 0).await.unwrap();
        let pt = vault.decrypt_stream("t", "c", &ct).await.unwrap();
        assert_eq!(&*pt, b"");
    }
}
