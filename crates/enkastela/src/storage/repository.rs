//! Trait-based key repository with an in-memory implementation.
//!
//! The [`KeyRepository`] trait abstracts key storage, enabling both PostgreSQL-backed
//! production deployments and [`InMemoryKeyRepository`] for testing and standalone usage.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::error::Error;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Key status lifecycle: Active -> Rotating -> Retired -> Destroyed.
///
/// Status transitions are one-way:
/// - `Active` -> `Rotating` (rotation started)
/// - `Rotating` -> `Retired` (rotation completed, old version kept for decryption)
/// - `Retired` -> `Destroyed` (crypto-shredded, key material zeroed)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key is in active use for both encryption and decryption.
    Active,
    /// Key is being rotated; a new version is being provisioned.
    Rotating,
    /// Key is retired; kept only for decrypting historical ciphertext.
    Retired,
    /// Key has been destroyed; key material has been zeroed.
    Destroyed,
}

/// The purpose a key serves in the encryption system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    /// Data Encryption Key — used for AES-GCM field encryption.
    Dek,
    /// Blind index key — used for deterministic HMAC-based searchable encryption.
    Blind,
    /// Tenant isolation key — per-tenant wrapping key for crypto-shredding.
    Tenant,
}

/// A stored key entry representing a versioned, wrapped key.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    /// Unique identifier for this key entry.
    pub id: String,
    /// The purpose this key serves (DEK, blind index, or tenant).
    pub purpose: KeyPurpose,
    /// The database table this key is scoped to, if any.
    pub table_name: Option<String>,
    /// The database column this key is scoped to, if any.
    pub column_name: Option<String>,
    /// Key version number (monotonically increasing per table+purpose).
    pub version: u32,
    /// The key material, wrapped (encrypted) under the master key.
    pub wrapped_key: Vec<u8>,
    /// Random salt used during key derivation.
    pub salt: Vec<u8>,
    /// Algorithm identifier (e.g., "aes-256-gcm").
    pub algorithm: String,
    /// Current lifecycle status of the key.
    pub status: KeyStatus,
    /// When this key entry was created.
    pub created_at: DateTime<Utc>,
    /// When this key was last rotated (new version created).
    pub rotated_at: Option<DateTime<Utc>>,
    /// When this key was destroyed (material zeroed).
    pub destroyed_at: Option<DateTime<Utc>>,
}

/// A stored tenant key entry for per-tenant crypto-shredding.
#[derive(Debug, Clone)]
pub struct TenantKeyEntry {
    /// Unique tenant identifier.
    pub tenant_id: String,
    /// The tenant key material, wrapped under the master key.
    pub wrapped_key: Vec<u8>,
    /// Random salt used during key derivation.
    pub salt: Vec<u8>,
    /// Current lifecycle status of the tenant key.
    pub status: KeyStatus,
    /// When this tenant key was created.
    pub created_at: DateTime<Utc>,
    /// When this tenant key was destroyed (material zeroed).
    pub destroyed_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstraction over key storage backends.
///
/// Implementations must be `Send + Sync` to support concurrent access from
/// async tasks. All methods return [`Error`] on failure.
#[async_trait]
pub trait KeyRepository: Send + Sync {
    /// Stores a new key entry.
    async fn store_key(&self, entry: KeyEntry) -> Result<(), Error>;

    /// Retrieves a key by table name, version, and purpose.
    ///
    /// Returns `None` if no matching key exists.
    async fn get_key(
        &self,
        table: &str,
        version: u32,
        purpose: KeyPurpose,
    ) -> Result<Option<KeyEntry>, Error>;

    /// Retrieves the currently active key for a table and purpose.
    ///
    /// Returns `None` if no active key exists.
    async fn get_active_key(
        &self,
        table: &str,
        purpose: KeyPurpose,
    ) -> Result<Option<KeyEntry>, Error>;

    /// Lists all keys for a given table, regardless of status.
    async fn list_keys(&self, table: &str) -> Result<Vec<KeyEntry>, Error>;

    /// Updates the status of a key identified by its ID.
    async fn update_key_status(&self, id: &str, status: KeyStatus) -> Result<(), Error>;

    /// Destroys a key by overwriting `wrapped_key` and `salt` with zeros,
    /// setting status to [`KeyStatus::Destroyed`], and recording the destruction time.
    async fn destroy_key(&self, id: &str) -> Result<(), Error>;

    /// Stores a new tenant key entry.
    async fn store_tenant_key(&self, entry: TenantKeyEntry) -> Result<(), Error>;

    /// Retrieves a tenant key by tenant ID.
    ///
    /// Returns `None` if no key exists for the tenant.
    async fn get_tenant_key(&self, tenant_id: &str) -> Result<Option<TenantKeyEntry>, Error>;

    /// Destroys a tenant key by overwriting `wrapped_key` and `salt` with zeros,
    /// setting status to [`KeyStatus::Destroyed`], and recording the destruction time.
    async fn destroy_tenant_key(&self, tenant_id: &str) -> Result<(), Error>;

    /// Lists all tenant keys, regardless of status.
    async fn list_tenant_keys(&self) -> Result<Vec<TenantKeyEntry>, Error>;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

/// In-memory key repository for testing and standalone usage.
///
/// Uses [`Mutex`]-guarded [`HashMap`]s for thread-safe concurrent access.
/// Not suitable for production — all data is lost when the process exits.
pub struct InMemoryKeyRepository {
    /// Keys indexed by their unique ID.
    keys: Mutex<HashMap<String, KeyEntry>>,
    /// Tenant keys indexed by tenant ID.
    tenant_keys: Mutex<HashMap<String, TenantKeyEntry>>,
}

impl InMemoryKeyRepository {
    /// Creates a new, empty in-memory repository.
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
            tenant_keys: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryKeyRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyRepository for InMemoryKeyRepository {
    async fn store_key(&self, entry: KeyEntry) -> Result<(), Error> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        keys.insert(entry.id.clone(), entry);
        Ok(())
    }

    async fn get_key(
        &self,
        table: &str,
        version: u32,
        purpose: KeyPurpose,
    ) -> Result<Option<KeyEntry>, Error> {
        let keys = self
            .keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        let found = keys.values().find(|k| {
            k.table_name.as_deref() == Some(table) && k.version == version && k.purpose == purpose
        });
        Ok(found.cloned())
    }

    async fn get_active_key(
        &self,
        table: &str,
        purpose: KeyPurpose,
    ) -> Result<Option<KeyEntry>, Error> {
        let keys = self
            .keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        let found = keys.values().find(|k| {
            k.table_name.as_deref() == Some(table)
                && k.purpose == purpose
                && k.status == KeyStatus::Active
        });
        Ok(found.cloned())
    }

    async fn list_keys(&self, table: &str) -> Result<Vec<KeyEntry>, Error> {
        let keys = self
            .keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        let result: Vec<KeyEntry> = keys
            .values()
            .filter(|k| k.table_name.as_deref() == Some(table))
            .cloned()
            .collect();
        Ok(result)
    }

    async fn update_key_status(&self, id: &str, status: KeyStatus) -> Result<(), Error> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        let entry = keys.get_mut(id).ok_or_else(|| Error::KeyNotFound {
            purpose: "unknown".to_string(),
            scope: id.to_string(),
        })?;
        entry.status = status;
        if status == KeyStatus::Rotating {
            entry.rotated_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn destroy_key(&self, id: &str) -> Result<(), Error> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        let entry = keys.get_mut(id).ok_or_else(|| Error::KeyNotFound {
            purpose: "unknown".to_string(),
            scope: id.to_string(),
        })?;
        if entry.status == KeyStatus::Destroyed {
            return Err(Error::KeyDestroyed);
        }
        // Zero out key material
        for byte in entry.wrapped_key.iter_mut() {
            *byte = 0;
        }
        for byte in entry.salt.iter_mut() {
            *byte = 0;
        }
        entry.status = KeyStatus::Destroyed;
        entry.destroyed_at = Some(Utc::now());
        Ok(())
    }

    async fn store_tenant_key(&self, entry: TenantKeyEntry) -> Result<(), Error> {
        let mut tenant_keys = self
            .tenant_keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        if let Some(existing) = tenant_keys.get(&entry.tenant_id) {
            if existing.status != KeyStatus::Destroyed {
                return Err(Error::TenantAlreadyErased(entry.tenant_id.clone()));
            }
        }
        tenant_keys.insert(entry.tenant_id.clone(), entry);
        Ok(())
    }

    async fn get_tenant_key(&self, tenant_id: &str) -> Result<Option<TenantKeyEntry>, Error> {
        let tenant_keys = self
            .tenant_keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        Ok(tenant_keys.get(tenant_id).cloned())
    }

    async fn destroy_tenant_key(&self, tenant_id: &str) -> Result<(), Error> {
        let mut tenant_keys = self
            .tenant_keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        let entry = tenant_keys
            .get_mut(tenant_id)
            .ok_or_else(|| Error::KeyNotFound {
                purpose: "tenant".to_string(),
                scope: tenant_id.to_string(),
            })?;
        if entry.status == KeyStatus::Destroyed {
            return Err(Error::TenantAlreadyErased(tenant_id.to_string()));
        }
        // Zero out key material
        for byte in entry.wrapped_key.iter_mut() {
            *byte = 0;
        }
        for byte in entry.salt.iter_mut() {
            *byte = 0;
        }
        entry.status = KeyStatus::Destroyed;
        entry.destroyed_at = Some(Utc::now());
        Ok(())
    }

    async fn list_tenant_keys(&self) -> Result<Vec<TenantKeyEntry>, Error> {
        let tenant_keys = self
            .tenant_keys
            .lock()
            .map_err(|e| Error::Database(e.to_string().into()))?;
        Ok(tenant_keys.values().cloned().collect())
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL implementation
// ---------------------------------------------------------------------------

/// PostgreSQL-backed key repository.
///
/// Stores keys in the `enkastela.keys` and `enkastela.tenant_keys` tables.
/// Run [`super::migrations::run_all`] before using this repository.
pub struct PostgresKeyRepository {
    pool: sqlx::PgPool,
}

impl PostgresKeyRepository {
    /// Creates a new repository backed by the given connection pool.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl KeyPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            KeyPurpose::Dek => "dek",
            KeyPurpose::Blind => "blind",
            KeyPurpose::Tenant => "tenant",
        }
    }

    fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "dek" => Ok(KeyPurpose::Dek),
            "blind" => Ok(KeyPurpose::Blind),
            "tenant" => Ok(KeyPurpose::Tenant),
            _ => Err(Error::InvalidInput(format!("unknown key purpose: {s}"))),
        }
    }
}

impl KeyStatus {
    fn as_str(&self) -> &'static str {
        match self {
            KeyStatus::Active => "active",
            KeyStatus::Rotating => "rotating",
            KeyStatus::Retired => "retired",
            KeyStatus::Destroyed => "destroyed",
        }
    }

    fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "active" => Ok(KeyStatus::Active),
            "rotating" => Ok(KeyStatus::Rotating),
            "retired" => Ok(KeyStatus::Retired),
            "destroyed" => Ok(KeyStatus::Destroyed),
            _ => Err(Error::InvalidInput(format!("unknown key status: {s}"))),
        }
    }
}

#[async_trait]
impl KeyRepository for PostgresKeyRepository {
    async fn store_key(&self, entry: KeyEntry) -> Result<(), Error> {
        sqlx::query(
            r#"INSERT INTO enkastela.keys
                (id, purpose, table_name, column_name, version, wrapped_key, salt, algorithm, status, created_at, rotated_at, destroyed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&entry.id)
        .bind(entry.purpose.as_str())
        .bind(&entry.table_name)
        .bind(&entry.column_name)
        .bind(entry.version as i32)
        .bind(&entry.wrapped_key)
        .bind(&entry.salt)
        .bind(&entry.algorithm)
        .bind(entry.status.as_str())
        .bind(entry.created_at)
        .bind(entry.rotated_at)
        .bind(entry.destroyed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;
        Ok(())
    }

    async fn get_key(
        &self,
        table: &str,
        version: u32,
        purpose: KeyPurpose,
    ) -> Result<Option<KeyEntry>, Error> {
        let row: Option<PgKeyRow> = sqlx::query_as(
            r#"SELECT id, purpose, table_name, column_name, version, wrapped_key, salt,
                      algorithm, status, created_at, rotated_at, destroyed_at
               FROM enkastela.keys
               WHERE table_name = $1 AND version = $2 AND purpose = $3"#,
        )
        .bind(table)
        .bind(version as i32)
        .bind(purpose.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        row.map(|r| r.into_entry()).transpose()
    }

    async fn get_active_key(
        &self,
        table: &str,
        purpose: KeyPurpose,
    ) -> Result<Option<KeyEntry>, Error> {
        let row: Option<PgKeyRow> = sqlx::query_as(
            r#"SELECT id, purpose, table_name, column_name, version, wrapped_key, salt,
                      algorithm, status, created_at, rotated_at, destroyed_at
               FROM enkastela.keys
               WHERE table_name = $1 AND purpose = $2 AND status = 'active'
               ORDER BY version DESC
               LIMIT 1"#,
        )
        .bind(table)
        .bind(purpose.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        row.map(|r| r.into_entry()).transpose()
    }

    async fn list_keys(&self, table: &str) -> Result<Vec<KeyEntry>, Error> {
        let rows: Vec<PgKeyRow> = sqlx::query_as(
            r#"SELECT id, purpose, table_name, column_name, version, wrapped_key, salt,
                      algorithm, status, created_at, rotated_at, destroyed_at
               FROM enkastela.keys
               WHERE table_name = $1
               ORDER BY version"#,
        )
        .bind(table)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    async fn update_key_status(&self, id: &str, status: KeyStatus) -> Result<(), Error> {
        let rotated_at: Option<DateTime<Utc>> = if status == KeyStatus::Rotating {
            Some(Utc::now())
        } else {
            None
        };

        let result = sqlx::query(
            r#"UPDATE enkastela.keys
               SET status = $1, rotated_at = COALESCE($2, rotated_at)
               WHERE id = $3"#,
        )
        .bind(status.as_str())
        .bind(rotated_at)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        if result.rows_affected() == 0 {
            return Err(Error::KeyNotFound {
                purpose: "unknown".into(),
                scope: id.into(),
            });
        }
        Ok(())
    }

    async fn destroy_key(&self, id: &str) -> Result<(), Error> {
        // Check current status first
        let row: Option<(String,)> =
            sqlx::query_as("SELECT status FROM enkastela.keys WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Database(Box::new(e)))?;

        match row {
            None => {
                return Err(Error::KeyNotFound {
                    purpose: "unknown".into(),
                    scope: id.into(),
                })
            }
            Some((status,)) if status == "destroyed" => return Err(Error::KeyDestroyed),
            _ => {}
        }

        // Zero out key material and mark destroyed
        sqlx::query(
            r#"UPDATE enkastela.keys
               SET wrapped_key = '\x00',
                   salt = '\x00',
                   status = 'destroyed',
                   destroyed_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        Ok(())
    }

    async fn store_tenant_key(&self, entry: TenantKeyEntry) -> Result<(), Error> {
        sqlx::query(
            r#"INSERT INTO enkastela.tenant_keys
                (tenant_id, wrapped_key, salt, status, created_at, destroyed_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant_id) DO NOTHING"#,
        )
        .bind(&entry.tenant_id)
        .bind(&entry.wrapped_key)
        .bind(&entry.salt)
        .bind(entry.status.as_str())
        .bind(entry.created_at)
        .bind(entry.destroyed_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;
        Ok(())
    }

    async fn get_tenant_key(&self, tenant_id: &str) -> Result<Option<TenantKeyEntry>, Error> {
        let row: Option<PgTenantRow> = sqlx::query_as(
            r#"SELECT tenant_id, wrapped_key, salt, status, created_at, destroyed_at
               FROM enkastela.tenant_keys
               WHERE tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        row.map(|r| r.into_entry()).transpose()
    }

    async fn destroy_tenant_key(&self, tenant_id: &str) -> Result<(), Error> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT status FROM enkastela.tenant_keys WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Database(Box::new(e)))?;

        match row {
            None => {
                return Err(Error::KeyNotFound {
                    purpose: "tenant".into(),
                    scope: tenant_id.into(),
                })
            }
            Some((status,)) if status == "destroyed" => {
                return Err(Error::TenantAlreadyErased(tenant_id.into()))
            }
            _ => {}
        }

        sqlx::query(
            r#"UPDATE enkastela.tenant_keys
               SET wrapped_key = '\x00',
                   salt = '\x00',
                   status = 'destroyed',
                   destroyed_at = now()
               WHERE tenant_id = $1"#,
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        Ok(())
    }

    async fn list_tenant_keys(&self) -> Result<Vec<TenantKeyEntry>, Error> {
        let rows: Vec<PgTenantRow> = sqlx::query_as(
            r#"SELECT tenant_id, wrapped_key, salt, status, created_at, destroyed_at
               FROM enkastela.tenant_keys
               ORDER BY created_at"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }
}

/// Internal row type for sqlx deserialization of `enkastela.keys`.
#[derive(sqlx::FromRow)]
struct PgKeyRow {
    id: String,
    purpose: String,
    table_name: Option<String>,
    column_name: Option<String>,
    version: i32,
    wrapped_key: Vec<u8>,
    salt: Vec<u8>,
    algorithm: String,
    status: String,
    created_at: DateTime<Utc>,
    rotated_at: Option<DateTime<Utc>>,
    destroyed_at: Option<DateTime<Utc>>,
}

impl PgKeyRow {
    fn into_entry(self) -> Result<KeyEntry, Error> {
        Ok(KeyEntry {
            id: self.id,
            purpose: KeyPurpose::parse(&self.purpose)?,
            table_name: self.table_name,
            column_name: self.column_name,
            version: self.version as u32,
            wrapped_key: self.wrapped_key,
            salt: self.salt,
            algorithm: self.algorithm,
            status: KeyStatus::parse(&self.status)?,
            created_at: self.created_at,
            rotated_at: self.rotated_at,
            destroyed_at: self.destroyed_at,
        })
    }
}

/// Internal row type for sqlx deserialization of `enkastela.tenant_keys`.
#[derive(sqlx::FromRow)]
struct PgTenantRow {
    tenant_id: String,
    wrapped_key: Vec<u8>,
    salt: Vec<u8>,
    status: String,
    created_at: DateTime<Utc>,
    destroyed_at: Option<DateTime<Utc>>,
}

impl PgTenantRow {
    fn into_entry(self) -> Result<TenantKeyEntry, Error> {
        Ok(TenantKeyEntry {
            tenant_id: self.tenant_id,
            wrapped_key: self.wrapped_key,
            salt: self.salt,
            status: KeyStatus::parse(&self.status)?,
            created_at: self.created_at,
            destroyed_at: self.destroyed_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key_entry(
        id: &str,
        table: &str,
        version: u32,
        purpose: KeyPurpose,
        status: KeyStatus,
    ) -> KeyEntry {
        KeyEntry {
            id: id.to_string(),
            purpose,
            table_name: Some(table.to_string()),
            column_name: Some("email".to_string()),
            version,
            wrapped_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            salt: vec![0xCA, 0xFE, 0xBA, 0xBE],
            algorithm: "aes-256-gcm".to_string(),
            status,
            created_at: Utc::now(),
            rotated_at: None,
            destroyed_at: None,
        }
    }

    fn make_tenant_entry(tenant_id: &str) -> TenantKeyEntry {
        TenantKeyEntry {
            tenant_id: tenant_id.to_string(),
            wrapped_key: vec![0x11, 0x22, 0x33, 0x44],
            salt: vec![0x55, 0x66, 0x77, 0x88],
            status: KeyStatus::Active,
            created_at: Utc::now(),
            destroyed_at: None,
        }
    }

    #[tokio::test]
    async fn store_and_retrieve_key() {
        let repo = InMemoryKeyRepository::new();
        let entry = make_key_entry("k1", "users", 1, KeyPurpose::Dek, KeyStatus::Active);

        repo.store_key(entry.clone()).await.unwrap();

        let retrieved = repo
            .get_key("users", 1, KeyPurpose::Dek)
            .await
            .unwrap()
            .expect("key should exist");

        assert_eq!(retrieved.id, "k1");
        assert_eq!(retrieved.version, 1);
        assert_eq!(retrieved.purpose, KeyPurpose::Dek);
        assert_eq!(retrieved.wrapped_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(retrieved.salt, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(retrieved.algorithm, "aes-256-gcm");
        assert_eq!(retrieved.status, KeyStatus::Active);
    }

    #[tokio::test]
    async fn get_active_key_returns_correct_one() {
        let repo = InMemoryKeyRepository::new();

        // Store an active key and a retired key for the same table
        let active = make_key_entry("k1", "users", 2, KeyPurpose::Dek, KeyStatus::Active);
        let retired = make_key_entry("k2", "users", 1, KeyPurpose::Dek, KeyStatus::Retired);

        repo.store_key(active).await.unwrap();
        repo.store_key(retired).await.unwrap();

        let result = repo
            .get_active_key("users", KeyPurpose::Dek)
            .await
            .unwrap()
            .expect("active key should exist");

        assert_eq!(result.id, "k1");
        assert_eq!(result.version, 2);
        assert_eq!(result.status, KeyStatus::Active);
    }

    #[tokio::test]
    async fn list_keys_for_table() {
        let repo = InMemoryKeyRepository::new();

        repo.store_key(make_key_entry(
            "k1",
            "users",
            1,
            KeyPurpose::Dek,
            KeyStatus::Active,
        ))
        .await
        .unwrap();
        repo.store_key(make_key_entry(
            "k2",
            "users",
            2,
            KeyPurpose::Dek,
            KeyStatus::Retired,
        ))
        .await
        .unwrap();
        repo.store_key(make_key_entry(
            "k3",
            "orders",
            1,
            KeyPurpose::Dek,
            KeyStatus::Active,
        ))
        .await
        .unwrap();

        let user_keys = repo.list_keys("users").await.unwrap();
        assert_eq!(user_keys.len(), 2);

        let order_keys = repo.list_keys("orders").await.unwrap();
        assert_eq!(order_keys.len(), 1);
    }

    #[tokio::test]
    async fn update_key_status_lifecycle() {
        let repo = InMemoryKeyRepository::new();
        let entry = make_key_entry("k1", "users", 1, KeyPurpose::Dek, KeyStatus::Active);
        repo.store_key(entry).await.unwrap();

        // Active -> Rotating
        repo.update_key_status("k1", KeyStatus::Rotating)
            .await
            .unwrap();
        let k = repo
            .get_key("users", 1, KeyPurpose::Dek)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(k.status, KeyStatus::Rotating);
        assert!(k.rotated_at.is_some());

        // Rotating -> Retired
        repo.update_key_status("k1", KeyStatus::Retired)
            .await
            .unwrap();
        let k = repo
            .get_key("users", 1, KeyPurpose::Dek)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(k.status, KeyStatus::Retired);

        // Retired -> Destroyed (via update_key_status, not destroy_key)
        repo.update_key_status("k1", KeyStatus::Destroyed)
            .await
            .unwrap();
        let k = repo
            .get_key("users", 1, KeyPurpose::Dek)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(k.status, KeyStatus::Destroyed);
    }

    #[tokio::test]
    async fn destroy_key_zeros_out_material() {
        let repo = InMemoryKeyRepository::new();
        let entry = make_key_entry("k1", "users", 1, KeyPurpose::Dek, KeyStatus::Active);
        let key_len = entry.wrapped_key.len();
        let salt_len = entry.salt.len();
        repo.store_key(entry).await.unwrap();

        repo.destroy_key("k1").await.unwrap();

        let destroyed = repo
            .get_key("users", 1, KeyPurpose::Dek)
            .await
            .unwrap()
            .expect("destroyed key entry should still exist");

        assert_eq!(destroyed.status, KeyStatus::Destroyed);
        assert!(destroyed.destroyed_at.is_some());
        assert_eq!(destroyed.wrapped_key, vec![0u8; key_len]);
        assert_eq!(destroyed.salt, vec![0u8; salt_len]);
    }

    #[tokio::test]
    async fn store_and_retrieve_tenant_key() {
        let repo = InMemoryKeyRepository::new();
        let entry = make_tenant_entry("tenant-42");
        repo.store_tenant_key(entry).await.unwrap();

        let retrieved = repo
            .get_tenant_key("tenant-42")
            .await
            .unwrap()
            .expect("tenant key should exist");

        assert_eq!(retrieved.tenant_id, "tenant-42");
        assert_eq!(retrieved.wrapped_key, vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(retrieved.salt, vec![0x55, 0x66, 0x77, 0x88]);
        assert_eq!(retrieved.status, KeyStatus::Active);
    }

    #[tokio::test]
    async fn destroy_tenant_key_zeros_out_material() {
        let repo = InMemoryKeyRepository::new();
        let entry = make_tenant_entry("tenant-42");
        let key_len = entry.wrapped_key.len();
        let salt_len = entry.salt.len();
        repo.store_tenant_key(entry).await.unwrap();

        repo.destroy_tenant_key("tenant-42").await.unwrap();

        let destroyed = repo
            .get_tenant_key("tenant-42")
            .await
            .unwrap()
            .expect("destroyed tenant key entry should still exist");

        assert_eq!(destroyed.status, KeyStatus::Destroyed);
        assert!(destroyed.destroyed_at.is_some());
        assert_eq!(destroyed.wrapped_key, vec![0u8; key_len]);
        assert_eq!(destroyed.salt, vec![0u8; salt_len]);
    }

    #[tokio::test]
    async fn get_nonexistent_key_returns_none() {
        let repo = InMemoryKeyRepository::new();

        let result = repo
            .get_key("nonexistent", 1, KeyPurpose::Dek)
            .await
            .unwrap();
        assert!(result.is_none());

        let active = repo
            .get_active_key("nonexistent", KeyPurpose::Dek)
            .await
            .unwrap();
        assert!(active.is_none());

        let tenant = repo.get_tenant_key("nonexistent-tenant").await.unwrap();
        assert!(tenant.is_none());
    }

    #[tokio::test]
    async fn destroy_nonexistent_key_returns_error() {
        let repo = InMemoryKeyRepository::new();

        let result = repo.destroy_key("no-such-key").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn destroy_already_destroyed_key_returns_error() {
        let repo = InMemoryKeyRepository::new();
        let entry = make_key_entry("k1", "users", 1, KeyPurpose::Dek, KeyStatus::Active);
        repo.store_key(entry).await.unwrap();

        repo.destroy_key("k1").await.unwrap();
        let result = repo.destroy_key("k1").await;
        assert!(matches!(result, Err(Error::KeyDestroyed)));
    }

    #[tokio::test]
    async fn destroy_already_destroyed_tenant_key_returns_error() {
        let repo = InMemoryKeyRepository::new();
        let entry = make_tenant_entry("tenant-42");
        repo.store_tenant_key(entry).await.unwrap();

        repo.destroy_tenant_key("tenant-42").await.unwrap();
        let result = repo.destroy_tenant_key("tenant-42").await;
        assert!(matches!(result, Err(Error::TenantAlreadyErased(_))));
    }

    #[tokio::test]
    async fn list_tenant_keys_returns_all() {
        let repo = InMemoryKeyRepository::new();
        repo.store_tenant_key(make_tenant_entry("t1"))
            .await
            .unwrap();
        repo.store_tenant_key(make_tenant_entry("t2"))
            .await
            .unwrap();
        repo.store_tenant_key(make_tenant_entry("t3"))
            .await
            .unwrap();

        let all = repo.list_tenant_keys().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn get_active_key_respects_purpose() {
        let repo = InMemoryKeyRepository::new();

        let dek = make_key_entry("k1", "users", 1, KeyPurpose::Dek, KeyStatus::Active);
        let blind = make_key_entry("k2", "users", 1, KeyPurpose::Blind, KeyStatus::Active);
        repo.store_key(dek).await.unwrap();
        repo.store_key(blind).await.unwrap();

        let dek_result = repo
            .get_active_key("users", KeyPurpose::Dek)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dek_result.id, "k1");

        let blind_result = repo
            .get_active_key("users", KeyPurpose::Blind)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blind_result.id, "k2");

        let tenant_result = repo
            .get_active_key("users", KeyPurpose::Tenant)
            .await
            .unwrap();
        assert!(tenant_result.is_none());
    }
}
