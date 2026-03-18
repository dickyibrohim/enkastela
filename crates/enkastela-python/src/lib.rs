//! # enkastela (Python)
//!
//! Python bindings for the Enkastela field encryption library.
//!
//! Install: `pip install enkastela`
//!
//! ## Usage
//!
//! ```python
//! from enkastela import Vault
//!
//! vault = Vault("postgres://localhost/mydb", master_key_hex="...")
//!
//! ciphertext = vault.encrypt("users", "email", b"alice@example.com")
//! plaintext = vault.decrypt("users", "email", ciphertext)
//! assert plaintext == b"alice@example.com"
//!
//! blind = vault.blind_index("users", "email", b"alice@example.com")
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use enkastela::crypto::aead;
use enkastela::crypto::hmac as ek_hmac;
use enkastela::crypto::kdf;
use enkastela::crypto::secret::SecretKey;
use enkastela::crypto::siv;
use enkastela::storage::codec;

/// Low-level encryption functions — no database required.
///
/// For production use with PostgreSQL, use the full Vault via async runtime.
/// This module provides standalone encrypt/decrypt for embedding scenarios.
#[pyclass]
struct CryptoEngine {
    master_key: SecretKey,
}

#[pymethods]
impl CryptoEngine {
    /// Create a new CryptoEngine with a 32-byte hex master key.
    #[new]
    fn new(master_key_hex: &str) -> PyResult<Self> {
        let bytes = hex_decode(master_key_hex)?;
        if bytes.len() != 32 {
            return Err(PyValueError::new_err("master key must be exactly 32 bytes (64 hex chars)"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            master_key: SecretKey::from_bytes(arr),
        })
    }

    /// Encrypt plaintext for a (table, column) pair using AES-256-GCM.
    ///
    /// Returns the ciphertext as bytes.
    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        table: &str,
        column: &str,
        plaintext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let dek = derive_dek(&self.master_key, table)?;
        let aad = format!("{}.{}", table, column);
        let ciphertext =
            aead::encrypt(&dek, plaintext, aad.as_bytes()).map_err(to_pyerr)?;
        let wire = codec::encode_wire_payload(1, &ciphertext);
        Ok(PyBytes::new(py, &wire))
    }

    /// Decrypt ciphertext for a (table, column) pair.
    ///
    /// Returns the plaintext as bytes.
    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        table: &str,
        column: &str,
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let payload = codec::decode_wire_payload(ciphertext).map_err(to_pyerr)?;
        let dek = derive_dek(&self.master_key, table)?;
        let aad = format!("{}.{}", table, column);
        let plaintext =
            aead::decrypt(&dek, &payload.ciphertext, aad.as_bytes()).map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &plaintext))
    }

    /// Encrypt deterministically using AES-256-SIV.
    ///
    /// Same plaintext + same key + same AAD = same ciphertext.
    /// Useful for unique constraints and equality lookups.
    fn encrypt_deterministic<'py>(
        &self,
        py: Python<'py>,
        table: &str,
        column: &str,
        plaintext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let dek = derive_dek(&self.master_key, table)?;
        let aad = format!("{}.{}", table, column);
        // SIV needs 64-byte key (two 32-byte sub-keys)
        let mut siv_key = [0u8; 64];
        siv_key[..32].copy_from_slice(dek.as_bytes());
        let extra = kdf::derive_key(&self.master_key, format!("{table}.siv").as_bytes())
            .map_err(to_pyerr)?;
        siv_key[32..].copy_from_slice(extra.as_bytes());
        let ct = siv::encrypt_siv(&siv_key, plaintext, &[aad.as_bytes()])
            .map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &ct))
    }

    /// Compute a blind index (HMAC-SHA256 truncated to 16 bytes).
    fn blind_index<'py>(
        &self,
        py: Python<'py>,
        table: &str,
        column: &str,
        plaintext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let index_key = kdf::derive_key(
            &self.master_key,
            format!("{table}.{column}.blind").as_bytes(),
        )
        .map_err(to_pyerr)?;
        let index = ek_hmac::compute_blind_index(&index_key, plaintext);
        Ok(PyBytes::new(py, &index))
    }

    /// Encode ciphertext to a base64 string with `ek:` prefix.
    fn encode_base64(&self, ciphertext: &[u8]) -> String {
        format!("ek:{}", BASE64.encode(ciphertext))
    }

    /// Decode a base64 string with `ek:` prefix to raw bytes.
    fn decode_base64<'py>(&self, py: Python<'py>, encoded: &str) -> PyResult<Bound<'py, PyBytes>> {
        let data = encoded
            .strip_prefix("ek:")
            .ok_or_else(|| PyValueError::new_err("missing 'ek:' prefix"))?;
        let bytes = BASE64
            .decode(data)
            .map_err(|e| PyValueError::new_err(format!("invalid base64: {e}")))?;
        Ok(PyBytes::new(py, &bytes))
    }
}

fn derive_dek(master: &SecretKey, table: &str) -> PyResult<SecretKey> {
    kdf::derive_key(master, table.as_bytes()).map_err(to_pyerr)
}

fn to_pyerr(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(format!("{e}"))
}

fn hex_decode(hex: &str) -> PyResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(PyValueError::new_err("hex string must have even length"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| PyValueError::new_err("invalid hex character"))
        })
        .collect()
}

/// Enkastela Python module.
#[pymodule]
fn enkastela(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CryptoEngine>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_valid() {
        let result = hex_decode("0102030405").unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn hex_decode_invalid_length() {
        assert!(hex_decode("012").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars() {
        assert!(hex_decode("zzzz").is_err());
    }

    #[test]
    fn derive_dek_deterministic() {
        let key = SecretKey::from_bytes([0xAA; 32]);
        let dek1 = derive_dek(&key, "users").unwrap();
        let dek2 = derive_dek(&key, "users").unwrap();
        assert_eq!(dek1.as_bytes(), dek2.as_bytes());
    }

    #[test]
    fn derive_dek_different_tables() {
        let key = SecretKey::from_bytes([0xAA; 32]);
        let dek1 = derive_dek(&key, "users").unwrap();
        let dek2 = derive_dek(&key, "orders").unwrap();
        assert_ne!(dek1.as_bytes(), dek2.as_bytes());
    }
}
