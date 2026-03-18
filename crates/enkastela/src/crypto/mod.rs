//! Cryptographic primitives for enkastela.
//!
//! All implementations delegate to audited RustCrypto crates.
//!
//! # Modules
//!
//! - [`secret`] — `SecretKey` with automatic zeroization
//! - [`aead`] — AES-256-GCM authenticated encryption
//! - [`siv`] — AES-256-SIV deterministic encryption
//! - [`kdf`] — HKDF-SHA256 key derivation
//! - [`wrap`] — AES-256 key wrapping (RFC 3394)
//! - [`hmac`] — HMAC-SHA256 for blind indexes
//! - [`nonce`] — CSPRNG nonce generation
//! - [`constant_time`] — constant-time comparison

pub mod aead;
pub mod backend;
pub mod constant_time;
pub mod hmac;
pub mod kdf;
pub mod nonce;
pub mod ore;
pub mod secret;
pub mod siv;
pub mod stream;
pub mod wrap;
