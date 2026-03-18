//! Configuration for enkastela.

use std::time::Duration;

/// Configuration for a Vault instance.
pub struct EnkastelaConfig {
    /// Database connection URL.
    pub database_url: Option<String>,
    /// Whether to require TLS for the database connection.
    pub require_tls: bool,
    /// Whether to run migrations on startup.
    pub auto_migrate: bool,
    /// Key cache TTL.
    pub cache_ttl: Duration,
    /// Maximum number of cached keys.
    pub cache_max_entries: usize,
    /// Whether audit logging is enabled.
    pub audit_enabled: bool,
    /// Database schema name.
    pub schema: String,
    /// Maximum payload size for encryption.
    pub max_payload_size: usize,
}

impl Default for EnkastelaConfig {
    fn default() -> Self {
        Self {
            database_url: None,
            require_tls: true,
            auto_migrate: true,
            cache_ttl: Duration::from_secs(300), // 5 minutes
            cache_max_entries: 1000,
            audit_enabled: true,
            schema: "enkastela".into(),
            max_payload_size: 16 * 1024 * 1024, // 16 MiB
        }
    }
}
