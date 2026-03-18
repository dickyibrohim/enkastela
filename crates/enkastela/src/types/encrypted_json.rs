//! Encrypted JSONB support.
//!
//! Selectively encrypt individual fields within a JSON object while leaving
//! the structure and non-sensitive fields in plaintext. This allows:
//!
//! - Querying on non-sensitive fields without decryption
//! - Encrypting only PII or sensitive values
//! - Preserving JSON structure for application logic
//!
//! # Example
//!
//! ```json
//! // Input
//! {"name": "Alice", "ssn": "123-45-6789", "age": 30}
//!
//! // After encrypting "ssn" field
//! {"name": "Alice", "ssn": "ek:1:v1:...", "age": 30}
//! ```
//!
//! # JSON Pointer
//!
//! Fields are addressed using JSON Pointer syntax (RFC 6901):
//! - `/ssn` — top-level field
//! - `/address/street` — nested field
//! - `/items/0/price` — array element

use serde_json::Value;

use crate::crypto::aead;
use crate::crypto::secret::SecretKey;
use crate::error::Error;
use crate::storage::codec::WirePayload;

/// Encrypts specific fields in a JSON value.
///
/// # Arguments
///
/// * `key` — encryption key
/// * `json` — the JSON value to process (modified in place)
/// * `table` — table name for AAD binding
/// * `version` — DEK version
/// * `field_paths` — JSON Pointer paths of fields to encrypt (e.g., `"/ssn"`, `"/address/street"`)
///
/// # Returns
///
/// The modified JSON value with specified fields encrypted.
pub fn encrypt_json_fields(
    key: &SecretKey,
    json: &mut Value,
    table: &str,
    version: u32,
    field_paths: &[&str],
) -> Result<(), Error> {
    for path in field_paths {
        if let Some(value) = pointer_mut(json, path) {
            let plaintext = value_to_bytes(value);
            let aad = build_json_aad(table, path);
            let raw_ct = aead::encrypt(key, &plaintext, &aad)?;
            let payload = WirePayload::new(version, raw_ct);
            *value = Value::String(payload.encode());
        }
    }
    Ok(())
}

/// Decrypts specific fields in a JSON value.
///
/// # Arguments
///
/// * `key` — decryption key (must match encryption key)
/// * `json` — the JSON value with encrypted fields
/// * `table` — table name for AAD binding (must match encryption)
/// * `field_paths` — JSON Pointer paths of fields to decrypt
pub fn decrypt_json_fields(
    key: &SecretKey,
    json: &mut Value,
    table: &str,
    field_paths: &[&str],
) -> Result<(), Error> {
    for path in field_paths {
        if let Some(value) = pointer_mut(json, path) {
            if let Value::String(s) = value.clone() {
                if WirePayload::is_encrypted(&s) {
                    let payload = WirePayload::decode(&s)?;
                    let aad = build_json_aad(table, path);
                    let plaintext = aead::decrypt(key, &payload.raw_ciphertext, &aad)?;
                    *value = bytes_to_value(&plaintext)?;
                }
            }
        }
    }
    Ok(())
}

/// Lists all encrypted fields in a JSON value.
///
/// Returns JSON Pointer paths for all string values that look like
/// enkastela-encrypted data.
pub fn find_encrypted_fields(json: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    find_encrypted_recursive(json, String::new(), &mut paths);
    paths
}

fn find_encrypted_recursive(value: &Value, current_path: String, paths: &mut Vec<String>) {
    match value {
        Value::String(s) if WirePayload::is_encrypted(s) => {
            paths.push(current_path);
        }
        Value::Object(map) => {
            for (key, val) in map {
                let child_path = format!("{}/{}", current_path, escape_json_pointer(key));
                find_encrypted_recursive(val, child_path, paths);
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let child_path = format!("{}/{}", current_path, i);
                find_encrypted_recursive(val, child_path, paths);
            }
        }
        _ => {}
    }
}

/// Builds AAD for a JSON field: `"json:{table}:{path}"`.
fn build_json_aad(table: &str, path: &str) -> Vec<u8> {
    format!("json:{}:{}", table, path).into_bytes()
}

/// Converts a JSON value to bytes for encryption.
fn value_to_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// Converts decrypted bytes back to a JSON value.
fn bytes_to_value(bytes: &[u8]) -> Result<Value, Error> {
    serde_json::from_slice(bytes).map_err(|_| Error::DecryptionFailed)
}

/// Escapes a JSON object key for use in a JSON Pointer (RFC 6901).
fn escape_json_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Navigates a JSON value by JSON Pointer path and returns a mutable reference.
fn pointer_mut<'a>(value: &'a mut Value, pointer: &str) -> Option<&'a mut Value> {
    if pointer.is_empty() || pointer == "/" {
        return Some(value);
    }

    let path = if let Some(stripped) = pointer.strip_prefix('/') {
        stripped
    } else {
        pointer
    };

    let mut current = value;
    for segment in path.split('/') {
        let unescaped = segment.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map.get_mut(&unescaped)?,
            Value::Array(arr) => {
                let idx: usize = unescaped.parse().ok()?;
                arr.get_mut(idx)?
            }
            _ => return None,
        };
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    #[test]
    fn encrypt_decrypt_single_field() {
        let key = test_key();
        let mut doc = json!({
            "name": "Alice",
            "ssn": "123-45-6789"
        });

        encrypt_json_fields(&key, &mut doc, "users", 1, &["/ssn"]).unwrap();

        // SSN should be encrypted
        assert!(doc["ssn"].as_str().unwrap().starts_with("ek:"));
        // Name should be untouched
        assert_eq!(doc["name"], "Alice");

        // Decrypt
        decrypt_json_fields(&key, &mut doc, "users", &["/ssn"]).unwrap();
        assert_eq!(doc["ssn"], "123-45-6789");
    }

    #[test]
    fn encrypt_decrypt_multiple_fields() {
        let key = test_key();
        let mut doc = json!({
            "name": "Alice",
            "email": "alice@example.com",
            "ssn": "123-45-6789",
            "age": 30
        });

        encrypt_json_fields(&key, &mut doc, "users", 1, &["/email", "/ssn"]).unwrap();

        assert!(doc["email"].as_str().unwrap().starts_with("ek:"));
        assert!(doc["ssn"].as_str().unwrap().starts_with("ek:"));
        assert_eq!(doc["name"], "Alice");
        assert_eq!(doc["age"], 30);

        decrypt_json_fields(&key, &mut doc, "users", &["/email", "/ssn"]).unwrap();
        assert_eq!(doc["email"], "alice@example.com");
        assert_eq!(doc["ssn"], "123-45-6789");
    }

    #[test]
    fn encrypt_nested_field() {
        let key = test_key();
        let mut doc = json!({
            "user": {
                "name": "Bob",
                "address": {
                    "street": "123 Main St",
                    "city": "Anytown"
                }
            }
        });

        encrypt_json_fields(&key, &mut doc, "data", 1, &["/user/address/street"]).unwrap();

        assert!(doc["user"]["address"]["street"]
            .as_str()
            .unwrap()
            .starts_with("ek:"));
        assert_eq!(doc["user"]["address"]["city"], "Anytown");
        assert_eq!(doc["user"]["name"], "Bob");

        decrypt_json_fields(&key, &mut doc, "data", &["/user/address/street"]).unwrap();
        assert_eq!(doc["user"]["address"]["street"], "123 Main St");
    }

    #[test]
    fn encrypt_numeric_field() {
        let key = test_key();
        let mut doc = json!({
            "name": "Alice",
            "salary": 75000
        });

        encrypt_json_fields(&key, &mut doc, "hr", 1, &["/salary"]).unwrap();
        assert!(doc["salary"].as_str().unwrap().starts_with("ek:"));

        decrypt_json_fields(&key, &mut doc, "hr", &["/salary"]).unwrap();
        assert_eq!(doc["salary"], 75000);
    }

    #[test]
    fn encrypt_boolean_field() {
        let key = test_key();
        let mut doc = json!({
            "name": "Alice",
            "is_vip": true
        });

        encrypt_json_fields(&key, &mut doc, "users", 1, &["/is_vip"]).unwrap();
        decrypt_json_fields(&key, &mut doc, "users", &["/is_vip"]).unwrap();
        assert_eq!(doc["is_vip"], true);
    }

    #[test]
    fn encrypt_array_element() {
        let key = test_key();
        let mut doc = json!({
            "items": [
                {"product": "Widget", "price": 9.99},
                {"product": "Gadget", "price": 29.99}
            ]
        });

        encrypt_json_fields(
            &key,
            &mut doc,
            "orders",
            1,
            &["/items/0/price", "/items/1/price"],
        )
        .unwrap();

        assert!(doc["items"][0]["price"]
            .as_str()
            .unwrap()
            .starts_with("ek:"));
        assert_eq!(doc["items"][0]["product"], "Widget");

        decrypt_json_fields(
            &key,
            &mut doc,
            "orders",
            &["/items/0/price", "/items/1/price"],
        )
        .unwrap();
        // Note: floating point comparison — JSON numbers may round-trip differently
        assert!((doc["items"][0]["price"].as_f64().unwrap() - 9.99).abs() < 0.001);
    }

    #[test]
    fn find_encrypted_fields_discovers_all() {
        let key = test_key();
        let mut doc = json!({
            "name": "Alice",
            "email": "alice@example.com",
            "nested": {
                "secret": "hidden"
            }
        });

        encrypt_json_fields(&key, &mut doc, "users", 1, &["/email", "/nested/secret"]).unwrap();

        let encrypted = find_encrypted_fields(&doc);
        assert_eq!(encrypted.len(), 2);
        assert!(encrypted.contains(&"/email".to_string()));
        assert!(encrypted.contains(&"/nested/secret".to_string()));
    }

    #[test]
    fn nonexistent_path_is_no_op() {
        let key = test_key();
        let mut doc = json!({"name": "Alice"});
        // Should not error on nonexistent path
        encrypt_json_fields(&key, &mut doc, "t", 1, &["/nonexistent"]).unwrap();
        assert_eq!(doc, json!({"name": "Alice"}));
    }

    #[test]
    fn wrong_table_decrypt_fails() {
        let key = test_key();
        let mut doc = json!({"secret": "data"});
        encrypt_json_fields(&key, &mut doc, "correct_table", 1, &["/secret"]).unwrap();

        let result = decrypt_json_fields(&key, &mut doc, "wrong_table", &["/secret"]);
        assert!(result.is_err());
    }

    #[test]
    fn json_pointer_escaping() {
        assert_eq!(escape_json_pointer("normal"), "normal");
        assert_eq!(escape_json_pointer("a/b"), "a~1b");
        assert_eq!(escape_json_pointer("a~b"), "a~0b");
        assert_eq!(escape_json_pointer("a~/b"), "a~0~1b");
    }
}
