//! Embedded SQL migrations for PostgreSQL.
//!
//! Migration constants are provided as static strings and can be executed against a
//! live PostgreSQL connection via [`run_all`].

/// Creates the `enkastela` schema if it does not already exist.
pub const CREATE_SCHEMA: &str = "CREATE SCHEMA IF NOT EXISTS enkastela;";

/// Creates the `enkastela.keys` table for storing wrapped DEK, blind-index, and tenant keys.
///
/// Columns:
/// - `id` — unique key identifier
/// - `purpose` — one of `dek`, `blind`, or `tenant`
/// - `table_name` / `column_name` — scope the key to a specific table/column
/// - `version` — monotonically increasing version per (table, purpose) pair
/// - `wrapped_key` — key material encrypted under the master key
/// - `salt` — random salt used during key derivation
/// - `algorithm` — encryption algorithm (default: `aes-256-gcm`)
/// - `status` — lifecycle status: `active`, `rotating`, `retired`, or `destroyed`
/// - `created_at` / `rotated_at` / `destroyed_at` — lifecycle timestamps
pub const CREATE_KEYS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS enkastela.keys (
    id          TEXT        NOT NULL PRIMARY KEY,
    purpose     TEXT        NOT NULL CHECK (purpose IN ('dek', 'blind', 'tenant')),
    table_name  TEXT,
    column_name TEXT,
    version     INTEGER     NOT NULL DEFAULT 1 CHECK (version > 0),
    wrapped_key BYTEA       NOT NULL,
    salt        BYTEA       NOT NULL,
    algorithm   TEXT        NOT NULL DEFAULT 'aes-256-gcm',
    status      TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'rotating', 'retired', 'destroyed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    UNIQUE (table_name, version, purpose)
);
"#;

/// Creates the `enkastela.tenant_keys` table for per-tenant wrapping keys.
///
/// Each tenant gets exactly one row. When crypto-shredded, the `wrapped_key` and `salt`
/// are overwritten with zeros and the status is set to `destroyed`.
pub const CREATE_TENANT_KEYS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS enkastela.tenant_keys (
    tenant_id    TEXT        NOT NULL PRIMARY KEY,
    wrapped_key  BYTEA       NOT NULL,
    salt         BYTEA       NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'active'
                             CHECK (status IN ('active', 'destroyed')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    destroyed_at TIMESTAMPTZ
);
"#;

/// Creates the `enkastela.audit_log` table for cryptographic operation audit trails.
///
/// Every encryption, decryption, key rotation, and key destruction event is logged here.
/// The `details` column holds a JSONB payload with operation-specific metadata.
pub const CREATE_AUDIT_LOG_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS enkastela.audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    event_type  TEXT        NOT NULL,
    key_id      TEXT,
    tenant_id   TEXT,
    table_name  TEXT,
    column_name TEXT,
    performed_by TEXT,
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"#;

/// Creates the `enkastela.rotation_progress` table for tracking in-flight key rotations.
///
/// Ensures at most one rotation is active per table at any time, and records progress
/// so that interrupted rotations can be resumed.
pub const CREATE_ROTATION_PROGRESS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS enkastela.rotation_progress (
    id              BIGSERIAL   PRIMARY KEY,
    table_name      TEXT        NOT NULL,
    old_version     INTEGER     NOT NULL,
    new_version     INTEGER     NOT NULL,
    total_rows      BIGINT      NOT NULL DEFAULT 0,
    processed_rows  BIGINT      NOT NULL DEFAULT 0,
    status          TEXT        NOT NULL DEFAULT 'in_progress'
                                CHECK (status IN ('in_progress', 'completed', 'failed')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    UNIQUE (table_name, old_version, new_version)
);
"#;

/// Creates indexes for efficient key lookups and audit log queries.
pub const CREATE_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_keys_table_purpose_status
    ON enkastela.keys (table_name, purpose, status);

CREATE INDEX IF NOT EXISTS idx_keys_status
    ON enkastela.keys (status);

CREATE INDEX IF NOT EXISTS idx_tenant_keys_status
    ON enkastela.tenant_keys (status);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
    ON enkastela.audit_log (event_type, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_log_key_id
    ON enkastela.audit_log (key_id)
    WHERE key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id
    ON enkastela.audit_log (tenant_id)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rotation_progress_table_status
    ON enkastela.rotation_progress (table_name, status);
"#;

/// Returns all migration SQL statements in order.
///
/// The returned order is:
/// 1. Schema creation
/// 2. Keys table
/// 3. Tenant keys table
/// 4. Audit log table
/// 5. Rotation progress table
/// 6. Indexes
pub fn all_migrations() -> Vec<&'static str> {
    vec![
        CREATE_SCHEMA,
        CREATE_KEYS_TABLE,
        CREATE_TENANT_KEYS_TABLE,
        CREATE_AUDIT_LOG_TABLE,
        CREATE_ROTATION_PROGRESS_TABLE,
        CREATE_INDEXES,
    ]
}

/// Executes all migrations against the given connection pool.
///
/// Migrations are idempotent (`CREATE ... IF NOT EXISTS`) and safe to run
/// on every startup. Multi-statement blocks (like index creation) are split
/// and executed individually.
pub async fn run_all(pool: &sqlx::PgPool) -> Result<(), crate::error::Error> {
    for block in all_migrations() {
        // Split multi-statement blocks (e.g., CREATE_INDEXES) into individual
        // statements, since sqlx does not support multiple commands per query.
        for stmt in block.split(';') {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            sqlx::query(trimmed)
                .execute(pool)
                .await
                .map_err(|e| crate::error::Error::Database(Box::new(e)))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_migrations_is_non_empty() {
        let migrations = all_migrations();
        assert!(!migrations.is_empty());
        assert_eq!(migrations.len(), 6);
    }

    #[test]
    fn schema_creation_is_first() {
        let migrations = all_migrations();
        assert_eq!(migrations[0], CREATE_SCHEMA);
    }

    #[test]
    fn all_migrations_contain_sql() {
        for (i, migration) in all_migrations().iter().enumerate() {
            assert!(
                !migration.trim().is_empty(),
                "migration {} should not be empty",
                i
            );
        }
    }

    #[test]
    fn keys_table_has_required_columns() {
        assert!(CREATE_KEYS_TABLE.contains("id"));
        assert!(CREATE_KEYS_TABLE.contains("purpose"));
        assert!(CREATE_KEYS_TABLE.contains("table_name"));
        assert!(CREATE_KEYS_TABLE.contains("wrapped_key"));
        assert!(CREATE_KEYS_TABLE.contains("salt"));
        assert!(CREATE_KEYS_TABLE.contains("status"));
        assert!(CREATE_KEYS_TABLE.contains("version"));
    }

    #[test]
    fn tenant_keys_table_has_required_columns() {
        assert!(CREATE_TENANT_KEYS_TABLE.contains("tenant_id"));
        assert!(CREATE_TENANT_KEYS_TABLE.contains("wrapped_key"));
        assert!(CREATE_TENANT_KEYS_TABLE.contains("salt"));
        assert!(CREATE_TENANT_KEYS_TABLE.contains("status"));
    }

    #[test]
    fn indexes_are_created() {
        assert!(CREATE_INDEXES.contains("idx_keys_table_purpose_status"));
        assert!(CREATE_INDEXES.contains("idx_keys_status"));
        assert!(CREATE_INDEXES.contains("idx_tenant_keys_status"));
        assert!(CREATE_INDEXES.contains("idx_audit_log_event_type"));
        assert!(CREATE_INDEXES.contains("idx_rotation_progress_table_status"));
    }
}
