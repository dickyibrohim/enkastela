//! # enkastela (Node.js)
//!
//! Node.js bindings for the Enkastela field encryption library via NAPI-RS.
//!
//! ## Usage
//!
//! ```javascript
//! const { CryptoEngine } = require('enkastela');
//!
//! const engine = new CryptoEngine('aa'.repeat(32)); // 32-byte hex key
//!
//! const ciphertext = engine.encrypt('users', 'email', Buffer.from('alice@example.com'));
//! const plaintext = engine.decrypt('users', 'email', ciphertext);
//! console.log(plaintext.toString()); // 'alice@example.com'
//!
//! const index = engine.blindIndex('users', 'email', Buffer.from('alice@example.com'));
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use enkastela::crypto::aead;
use enkastela::crypto::hmac as ek_hmac;
use enkastela::crypto::kdf;
use enkastela::crypto::secret::SecretKey;
use enkastela::crypto::siv;
use enkastela::storage::codec;

/// Low-level encryption engine — no database required.
///
/// Provides standalone encrypt/decrypt for embedding in Node.js applications.
#[napi]
pub struct CryptoEngine {
    master_key: SecretKey,
}

#[napi]
impl CryptoEngine {
    /// Create a new CryptoEngine with a 32-byte hex master key.
    #[napi(constructor)]
    pub fn new(master_key_hex: String) -> Result<Self> {
        let bytes = hex_decode(&master_key_hex)?;
        if bytes.len() != 32 {
            return Err(Error::new(
                Status::InvalidArg,
                "master key must be exactly 32 bytes (64 hex chars)",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            master_key: SecretKey::from_bytes(arr),
        })
    }

    /// Encrypt plaintext for a (table, column) pair using AES-256-GCM.
    #[napi]
    pub fn encrypt(&self, table: String, column: String, plaintext: Buffer) -> Result<Buffer> {
        let dek = derive_dek(&self.master_key, &table)?;
        let aad = format!("{}.{}", table, column);
        let ciphertext =
            aead::encrypt(&dek, plaintext.as_ref(), aad.as_bytes()).map_err(to_napi_err)?;
        let wire = codec::encode_wire_payload(1, &ciphertext);
        Ok(Buffer::from(wire))
    }

    /// Decrypt ciphertext for a (table, column) pair.
    #[napi]
    pub fn decrypt(&self, table: String, column: String, ciphertext: Buffer) -> Result<Buffer> {
        let payload = codec::decode_wire_payload(ciphertext.as_ref()).map_err(to_napi_err)?;
        let dek = derive_dek(&self.master_key, &table)?;
        let aad = format!("{}.{}", table, column);
        let plaintext =
            aead::decrypt(&dek, &payload.ciphertext, aad.as_bytes()).map_err(to_napi_err)?;
        Ok(Buffer::from(plaintext.to_vec()))
    }

    /// Encrypt deterministically using AES-256-SIV.
    #[napi]
    pub fn encrypt_deterministic(
        &self,
        table: String,
        column: String,
        plaintext: Buffer,
    ) -> Result<Buffer> {
        let dek = derive_dek(&self.master_key, &table)?;
        let aad = format!("{}.{}", table, column);
        let mut siv_key = [0u8; 64];
        siv_key[..32].copy_from_slice(dek.as_bytes());
        let extra = kdf::derive_key(&self.master_key, format!("{table}.siv").as_bytes())
            .map_err(to_napi_err)?;
        siv_key[32..].copy_from_slice(extra.as_bytes());
        let ct = siv::encrypt_siv(&siv_key, plaintext.as_ref(), &[aad.as_bytes()])
            .map_err(to_napi_err)?;
        Ok(Buffer::from(ct))
    }

    /// Compute a blind index (HMAC-SHA256 truncated to 16 bytes).
    #[napi]
    pub fn blind_index(&self, table: String, column: String, plaintext: Buffer) -> Result<Buffer> {
        let index_key = kdf::derive_key(
            &self.master_key,
            format!("{table}.{column}.blind").as_bytes(),
        )
        .map_err(to_napi_err)?;
        let index = ek_hmac::compute_blind_index(&index_key, plaintext.as_ref());
        Ok(Buffer::from(index.to_vec()))
    }

    /// Encode ciphertext to base64 with `ek:` prefix.
    #[napi]
    pub fn encode_base64(&self, ciphertext: Buffer) -> String {
        format!("ek:{}", BASE64.encode(ciphertext.as_ref()))
    }

    /// Decode base64 with `ek:` prefix to raw bytes.
    #[napi]
    pub fn decode_base64(&self, encoded: String) -> Result<Buffer> {
        let data = encoded
            .strip_prefix("ek:")
            .ok_or_else(|| Error::new(Status::InvalidArg, "missing 'ek:' prefix"))?;
        let bytes = BASE64
            .decode(data)
            .map_err(|e| Error::new(Status::InvalidArg, format!("invalid base64: {e}")))?;
        Ok(Buffer::from(bytes))
    }
}

fn derive_dek(master: &SecretKey, table: &str) -> Result<SecretKey> {
    kdf::derive_key(master, table.as_bytes()).map_err(to_napi_err)
}

fn to_napi_err(e: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, format!("{e}"))
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(Error::new(
            Status::InvalidArg,
            "hex string must have even length",
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| Error::new(Status::InvalidArg, "invalid hex character"))
        })
        .collect()
}

// Note: Tests for NAPI bindings require a Node.js runtime.
// Unit tests for the underlying crypto are in the enkastela crate.
