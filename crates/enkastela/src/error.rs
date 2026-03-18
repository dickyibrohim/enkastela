//! Sanitized error types for enkastela.
//!
//! # Security
//!
//! Error variants are deliberately vague about cryptographic failures to prevent
//! oracle attacks. No variant ever contains key material, plaintext, or ciphertext bytes.

/// Boxed error type for wrapping external errors without exposing their details.
type BoxedError = Box<dyn std::error::Error + Send + Sync>;

/// All enkastela operations return `Result<T, Error>`.
///
/// Error messages are sanitized to prevent information leakage:
/// - Crypto errors do not distinguish between "wrong key" and "tampered ciphertext"
/// - Database errors wrap the inner error without exposing SQL details in Display
/// - No variant contains key bytes, plaintext bytes, or ciphertext bytes
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // --- Crypto errors (NEVER include key material or plaintext) ---
    /// Encryption operation failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failed due to authentication error.
    /// Deliberately does not distinguish between wrong key and tampered ciphertext.
    #[error("decryption failed: authentication error")]
    DecryptionFailed,

    /// Key derivation operation failed.
    #[error("key derivation failed")]
    KeyDerivationFailed,

    /// Key unwrap integrity check failed.
    #[error("key unwrap failed: integrity check error")]
    KeyUnwrapFailed,

    // --- Format errors ---
    /// The wire format string is invalid or malformed.
    #[error("invalid wire format")]
    InvalidWireFormat,

    /// The wire format version is not supported by this library version.
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u32),

    // --- Key management errors ---
    /// The requested key was not found in the keyring.
    #[error("key not found: {purpose}:{scope}")]
    KeyNotFound {
        /// Key purpose (e.g., "dek", "blind", "tenant").
        purpose: String,
        /// Key scope (e.g., table name or tenant ID).
        scope: String,
    },

    /// The requested key has been destroyed and cannot be used.
    #[error("key has been destroyed")]
    KeyDestroyed,

    /// The requested key version has been retired.
    #[error("key version {version} is retired for table {table}")]
    KeyRetired {
        /// Table name the key belongs to.
        table: String,
        /// The retired key version.
        version: u32,
    },

    // --- Database errors (sanitized) ---
    /// A database operation failed. The inner error is boxed to prevent
    /// leaking SQL details through the Display implementation.
    #[error("database operation failed")]
    Database(#[source] BoxedError),

    // --- Configuration errors ---
    /// Invalid configuration provided to the builder.
    #[error("configuration error: {0}")]
    Config(String),

    /// TLS is required but the connection string does not enforce it.
    #[error("TLS required but connection is not encrypted")]
    TlsRequired,

    // --- Input validation ---
    /// The plaintext payload exceeds the maximum allowed size.
    #[error("payload exceeds maximum size of {max_bytes} bytes")]
    PayloadTooLarge {
        /// Maximum allowed payload size in bytes.
        max_bytes: usize,
    },

    /// The provided input is invalid.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    // --- Operational errors ---
    /// The audit event queue is full and the operation timed out.
    #[error("audit queue full, operation timed out")]
    AuditQueueFull,

    /// A key rotation is already in progress for the specified table.
    #[error("rotation already in progress for table {0}")]
    RotationInProgress(String),

    /// The tenant's key has already been destroyed (crypto-shredded).
    #[error("tenant key already destroyed for tenant {0}")]
    TenantAlreadyErased(String),

    /// The master key provider failed to supply a key.
    #[error("master key provider failed")]
    ProviderFailed(#[source] BoxedError),

    /// Access denied by the field-level access control policy.
    #[error("access denied: role '{role}' cannot access {table}.{column}")]
    AccessDenied {
        /// The caller's role.
        role: String,
        /// The table name.
        table: String,
        /// The column name.
        column: String,
    },
}

impl Error {
    /// Returns `true` if the error is transient and the operation may succeed on retry.
    ///
    /// Transient errors include database connectivity issues and audit queue overflow.
    /// Permanent errors include cryptographic failures and configuration errors.
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Database(_) | Error::AuditQueueFull)
    }
}

/// Convenience type alias for enkastela results.
pub type Result<T> = std::result::Result<T, Error>;
