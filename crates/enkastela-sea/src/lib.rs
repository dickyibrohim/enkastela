//! # enkastela-sea
//!
//! SeaORM integration for Enkastela field encryption.
//!
//! Provides [`Encrypted`] as a custom SeaORM value type that stores
//! Enkastela ciphertext in TEXT columns.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sea_orm::entity::prelude::*;
//! use enkastela_sea::Encrypted;
//!
//! #[derive(Clone, Debug, DeriveEntityModel)]
//! #[sea_orm(table_name = "users")]
//! pub struct Model {
//!     #[sea_orm(primary_key)]
//!     pub id: i32,
//!     pub name: String,
//!     pub email: Encrypted,
//! }
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sea_orm::{TryGetError, TryGetable};
use std::fmt;

/// Wire format prefix.
const ENKASTELA_PREFIX: &str = "ek:";

/// A wrapper for encrypted field values in SeaORM entities.
///
/// Maps to TEXT in the database. Contains base64-encoded Enkastela wire format.
#[derive(Clone, PartialEq, Eq)]
pub struct Encrypted {
    ciphertext: Vec<u8>,
}

impl Encrypted {
    pub fn from_ciphertext(ciphertext: Vec<u8>) -> Self {
        Self { ciphertext }
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }

    pub fn to_encoded_string(&self) -> String {
        format!("{}{}", ENKASTELA_PREFIX, BASE64.encode(&self.ciphertext))
    }

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

impl fmt::Debug for Encrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Encrypted(<{} bytes>)", self.ciphertext.len())
    }
}

impl fmt::Display for Encrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_encoded_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptedError {
    #[error("missing 'ek:' prefix")]
    InvalidPrefix,
    #[error("invalid base64 encoding")]
    InvalidBase64,
}

// -- SeaORM integration --

impl From<Encrypted> for sea_orm::Value {
    fn from(enc: Encrypted) -> Self {
        sea_orm::Value::String(Some(Box::new(enc.to_encoded_string())))
    }
}

impl TryGetable for Encrypted {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &sea_orm::QueryResult,
        index: I,
    ) -> Result<Self, TryGetError> {
        let s: String = res.try_get_by(index).map_err(TryGetError::DbErr)?;
        Self::from_encoded_string(&s)
            .map_err(|e| TryGetError::DbErr(sea_orm::DbErr::Type(e.to_string())))
    }
}

impl sea_orm::sea_query::ValueType for Encrypted {
    fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            sea_orm::Value::String(Some(s)) => {
                Self::from_encoded_string(&s).map_err(|_| sea_orm::sea_query::ValueTypeErr)
            }
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        "Encrypted".to_string()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> sea_orm::sea_query::ColumnType {
        sea_orm::sea_query::ColumnType::Text
    }
}

impl sea_orm::sea_query::Nullable for Encrypted {
    fn null() -> sea_orm::Value {
        sea_orm::Value::String(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_roundtrip() {
        let data = vec![10, 20, 30, 40];
        let enc = Encrypted::from_ciphertext(data.clone());
        let encoded = enc.to_encoded_string();
        let decoded = Encrypted::from_encoded_string(&encoded).unwrap();
        assert_eq!(decoded.ciphertext(), &data);
    }

    #[test]
    fn encrypted_to_sea_value() {
        let enc = Encrypted::from_ciphertext(vec![1, 2, 3]);
        let val: sea_orm::Value = enc.into();
        match val {
            sea_orm::Value::String(Some(s)) => {
                assert!(s.starts_with("ek:"));
            }
            _ => panic!("expected String value"),
        }
    }

    #[test]
    fn encrypted_debug_hides_data() {
        let enc = Encrypted::from_ciphertext(vec![0; 48]);
        let debug = format!("{:?}", enc);
        assert!(debug.contains("48 bytes"));
    }

    #[test]
    fn value_type_name() {
        use sea_orm::sea_query::ValueType;
        assert_eq!(Encrypted::type_name(), "Encrypted");
    }
}
