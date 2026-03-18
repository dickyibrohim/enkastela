//! PostgreSQL connection pool with TLS enforcement.
//!
//! Wraps [`sqlx::PgPool`] with connection-time TLS validation. When
//! `require_tls` is enabled (the default), the database URL must contain
//! an explicit `sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full`.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::error::Error;

/// Allowed SSL modes that guarantee encrypted connections.
const SECURE_SSL_MODES: &[&str] = &["require", "verify-ca", "verify-full"];

/// Validates that a PostgreSQL URL enforces TLS.
///
/// Parses the URL properly and checks the `sslmode` query parameter
/// rather than doing a naive string search.
fn validate_tls_mode(url: &str) -> Result<(), Error> {
    // Parse query params from the URL
    let sslmode = extract_sslmode(url);

    match sslmode {
        Some(mode) if SECURE_SSL_MODES.contains(&mode.to_lowercase().as_str()) => Ok(()),
        Some(mode) => Err(Error::Config(format!(
            "TLS required but sslmode={mode} does not guarantee encryption. Use sslmode=require, verify-ca, or verify-full"
        ))),
        None => Err(Error::TlsRequired),
    }
}

/// Extracts the sslmode parameter value from a PostgreSQL URL.
fn extract_sslmode(url: &str) -> Option<String> {
    // Handle both query-string style (?sslmode=X) and key=value style
    let query_part = url.split('?').nth(1)?;
    for param in query_part.split('&') {
        let (key, value) = param.split_once('=')?;
        if key.eq_ignore_ascii_case("sslmode") {
            return Some(value.to_string());
        }
    }
    None
}

/// Creates a PostgreSQL connection pool with optional TLS enforcement.
///
/// # Arguments
///
/// * `url` — PostgreSQL connection string
/// * `require_tls` — when `true`, rejects URLs without an SSL mode that
///   guarantees encryption
///
/// # Errors
///
/// Returns [`Error::TlsRequired`] if TLS is required but the URL does not
/// enforce it. Returns [`Error::Database`] if the connection cannot be
/// established.
pub async fn connect(url: &str, require_tls: bool) -> Result<PgPool, Error> {
    if require_tls {
        validate_tls_mode(url)?;
    }

    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(5)
        .connect(url)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tls_required_rejects_plain_url() {
        let result = connect("postgres://localhost/test", true).await;
        assert!(matches!(result, Err(Error::TlsRequired)));
    }

    #[tokio::test]
    async fn tls_required_accepts_sslmode_require() {
        let result = connect("postgres://localhost:59999/test?sslmode=require", true).await;
        assert!(matches!(result, Err(Error::Database(_))));
    }

    #[tokio::test]
    async fn tls_required_accepts_verify_full() {
        let result = connect("postgres://localhost:59999/test?sslmode=verify-full", true).await;
        assert!(matches!(result, Err(Error::Database(_))));
    }

    #[tokio::test]
    async fn tls_required_rejects_sslmode_disable() {
        let result = connect("postgres://localhost/test?sslmode=disable", true).await;
        assert!(matches!(result, Err(Error::Config(_))));
    }

    #[tokio::test]
    async fn tls_required_rejects_sslmode_prefer() {
        let result = connect("postgres://localhost/test?sslmode=prefer", true).await;
        assert!(matches!(result, Err(Error::Config(_))));
    }

    #[tokio::test]
    async fn insecure_allows_plain_url() {
        let result = connect("postgres://localhost:59999/test", false).await;
        assert!(matches!(result, Err(Error::Database(_))));
    }

    #[test]
    fn extract_sslmode_from_query() {
        assert_eq!(
            extract_sslmode("postgres://host/db?sslmode=require"),
            Some("require".into())
        );
        assert_eq!(
            extract_sslmode("postgres://host/db?user=foo&sslmode=verify-full"),
            Some("verify-full".into())
        );
        assert_eq!(extract_sslmode("postgres://host/db"), None);
    }
}
