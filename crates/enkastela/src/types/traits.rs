//! Trait for types that can be encrypted by the Vault.

/// Encryption mode for a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    /// AES-256-GCM randomized encryption.
    Randomized,
    /// AES-256-GCM + HMAC-SHA256 blind index.
    Searchable,
    /// AES-256-SIV deterministic encryption.
    Deterministic,
}

/// Definition of an encrypted field.
pub struct FieldDef {
    /// Field name.
    pub name: &'static str,
    /// Encryption mode.
    pub mode: EncryptionMode,
}

/// Trait for structs that can have their fields encrypted/decrypted.
///
/// Typically derived via `#[derive(VaultEncrypt)]`.
pub trait VaultEncryptable {
    /// Returns the database table name.
    fn table_name() -> &'static str;
    /// Returns definitions of all encrypted fields.
    fn encrypted_fields() -> Vec<FieldDef>;
}
