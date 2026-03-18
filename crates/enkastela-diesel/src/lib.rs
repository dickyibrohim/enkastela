//! # enkastela-diesel
//!
//! Diesel integration for Enkastela field encryption.
//!
//! Provides the [`Encrypted`] type that implements Diesel's `ToSql`, `FromSql`,
//! and `AsExpression` traits for transparent encrypted field storage.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use enkastela_diesel::Encrypted;
//!
//! table! {
//!     users (id) {
//!         id -> Int4,
//!         name -> Text,
//!         email -> Text, // Encrypted<String> maps to Text
//!     }
//! }
//!
//! #[derive(Queryable)]
//! struct User {
//!     id: i32,
//!     name: String,
//!     email: Encrypted,
//! }
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use diesel::backend::Backend;
use diesel::deserialize::{self, FromSql};
use diesel::pg::Pg;
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;
use diesel::{AsExpression, FromSqlRow};
use std::fmt;

/// Wire format prefix for Enkastela encrypted fields.
const ENKASTELA_PREFIX: &str = "ek:";

/// A wrapper type for encrypted fields in Diesel queries.
///
/// Stored as TEXT in PostgreSQL. Contains the base64-encoded Enkastela
/// wire format ciphertext. Encrypt/decrypt via `Vault` before creating
/// or after reading this type.
#[derive(Debug, Clone, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = Text)]
pub struct Encrypted {
    /// Raw ciphertext bytes (wire format).
    ciphertext: Vec<u8>,
}

impl Encrypted {
    /// Creates an `Encrypted` from raw ciphertext bytes.
    pub fn from_ciphertext(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    /// Returns the raw ciphertext bytes.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes self and returns the ciphertext.
    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }

    /// Encodes as prefixed base64 string.
    pub fn to_encoded_string(&self) -> String {
        format!("{}{}", ENKASTELA_PREFIX, BASE64.encode(&self.ciphertext))
    }

    /// Decodes from prefixed base64 string.
    pub fn from_encoded_string(s: &str) -> Result<Self, EncryptedError> {
        let encoded = s
            .strip_prefix(ENKASTELA_PREFIX)
            .ok_or(EncryptedError::InvalidPrefix)?;
        let ciphertext = BASE64
            .decode(encoded)
            .map_err(|_| EncryptedError::InvalidBase64)?;
        Ok(Self { ciphertext })
    }
}

impl fmt::Display for Encrypted {
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

impl ToSql<Text, Pg> for Encrypted {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        let encoded = self.to_encoded_string();
        <str as ToSql<Text, Pg>>::to_sql(&encoded, &mut out.reborrow())
    }
}

impl FromSql<Text, Pg> for Encrypted {
    fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let s = <String as FromSql<Text, Pg>>::from_sql(bytes)?;
        Self::from_encoded_string(&s)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_roundtrip_encoding() {
        let original = vec![1, 2, 3, 4, 5];
        let enc = Encrypted::from_ciphertext(original.clone());
        let encoded = enc.to_encoded_string();

        assert!(encoded.starts_with("ek:"));

        let decoded = Encrypted::from_encoded_string(&encoded).unwrap();
        assert_eq!(decoded.ciphertext(), &original);
    }

    #[test]
    fn encrypted_invalid_prefix() {
        let result = Encrypted::from_encoded_string("invalid:abc");
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_display() {
        let enc = Encrypted::from_ciphertext(vec![0; 16]);
        assert_eq!(format!("{enc}"), "Encrypted(<16 bytes>)");
    }

    #[test]
    fn encrypted_clone_eq() {
        let a = Encrypted::from_ciphertext(vec![1, 2, 3]);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
