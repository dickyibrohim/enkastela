//! # enkastela-sqlx
//!
//! SQLx integration for Enkastela field encryption.
//!
//! Provides the [`Encrypted<T>`] wrapper type that implements SQLx's `Type`,
//! `Encode`, and `Decode` traits for transparent field encryption with PostgreSQL.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use enkastela_sqlx::Encrypted;
//!
//! #[derive(sqlx::FromRow)]
//! struct User {
//!     id: i64,
//!     name: String,
//!     email: Encrypted<String>,
//! }
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgHasArrayType, PgTypeInfo, PgValueRef};
use sqlx::{Database, Decode, Encode, Postgres, Type};
use std::fmt;
use std::marker::PhantomData;

/// Wire format prefix for Enkastela encrypted fields.
const ENKASTELA_PREFIX: &str = "ek:";

/// A wrapper type for encrypted fields in SQLx queries.
///
/// `Encrypted<T>` stores the raw encrypted ciphertext (base64-encoded wire format)
/// in a PostgreSQL `TEXT` column. The encryption/decryption happens outside of SQLx
/// via the Enkastela `Vault`.
///
/// When read from the database, the inner `ciphertext` contains the raw wire format
/// bytes. Use `Vault::decrypt_field()` to get the plaintext.
///
/// When writing to the database, first encrypt with `Vault::encrypt_field()` and
/// then create an `Encrypted::from_ciphertext()`.
#[derive(Clone, PartialEq, Eq)]
pub struct Encrypted<T> {
    /// The raw ciphertext bytes (wire format).
    ciphertext: Vec<u8>,
    /// Phantom for the original plaintext type.
    _phantom: PhantomData<T>,
}

impl<T> Encrypted<T> {
    /// Creates an `Encrypted` from raw ciphertext bytes.
    pub fn from_ciphertext(ciphertext: Vec<u8>) -> Self {
        Self {
            ciphertext,
            _phantom: PhantomData,
        }
    }

    /// Returns the raw ciphertext bytes.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes self and returns the ciphertext bytes.
    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }

    /// Returns the base64-encoded ciphertext with the Enkastela prefix.
    pub fn to_encoded_string(&self) -> String {
        format!("{}{}", ENKASTELA_PREFIX, BASE64.encode(&self.ciphertext))
    }

    /// Creates an `Encrypted` from a base64-encoded string with prefix.
    pub fn from_encoded_string(s: &str) -> Result<Self, EncryptedError> {
        let encoded = s
            .strip_prefix(ENKASTELA_PREFIX)
            .ok_or(EncryptedError::InvalidPrefix)?;
        let ciphertext = BASE64
            .decode(encoded)
            .map_err(|_| EncryptedError::InvalidBase64)?;
        Ok(Self::from_ciphertext(ciphertext))
    }
}

impl<T> fmt::Debug for Encrypted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Encrypted(<{} bytes>)", self.ciphertext.len())
    }
}

/// Errors from the `Encrypted` type.
#[derive(Debug, thiserror::Error)]
pub enum EncryptedError {
    #[error("missing 'ek:' prefix")]
    InvalidPrefix,
    #[error("invalid base64 encoding")]
    InvalidBase64,
}

// -- SQLx integration --

impl<T> Type<Postgres> for Encrypted<T> {
    fn type_info() -> PgTypeInfo {
        // Stored as TEXT in PostgreSQL
        <String as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

impl<T> PgHasArrayType for Encrypted<T> {
    fn array_type_info() -> PgTypeInfo {
        <String as PgHasArrayType>::array_type_info()
    }
}

impl<T> Encode<'_, Postgres> for Encrypted<T> {
    fn encode_by_ref(
        &self,
        buf: &mut <Postgres as Database>::ArgumentBuffer<'_>,
    ) -> Result<sqlx::encode::IsNull, BoxDynError> {
        let encoded = self.to_encoded_string();
        <String as Encode<'_, Postgres>>::encode(encoded, buf)
    }
}

impl<T> Decode<'_, Postgres> for Encrypted<T> {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        let s = <String as Decode<'_, Postgres>>::decode(value)?;
        Self::from_encoded_string(&s).map_err(|e| Box::new(e) as BoxDynError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_roundtrip_encoding() {
        let original = vec![1, 2, 3, 4, 5];
        let enc = Encrypted::<String>::from_ciphertext(original.clone());
        let encoded = enc.to_encoded_string();

        assert!(encoded.starts_with("ek:"));

        let decoded = Encrypted::<String>::from_encoded_string(&encoded).unwrap();
        assert_eq!(decoded.ciphertext(), &original);
    }

    #[test]
    fn encrypted_invalid_prefix() {
        let result = Encrypted::<String>::from_encoded_string("invalid:abc");
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_invalid_base64() {
        let result = Encrypted::<String>::from_encoded_string("ek:!@#$%not-base64");
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_debug_hides_data() {
        let enc = Encrypted::<String>::from_ciphertext(vec![0; 32]);
        let debug = format!("{:?}", enc);
        assert!(debug.contains("32 bytes"));
        assert!(!debug.contains('\0'));
    }

    #[test]
    fn encrypted_clone_eq() {
        let a = Encrypted::<String>::from_ciphertext(vec![1, 2, 3]);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn encrypted_into_ciphertext() {
        let original = vec![10, 20, 30];
        let enc = Encrypted::<String>::from_ciphertext(original.clone());
        assert_eq!(enc.into_ciphertext(), original);
    }
}
