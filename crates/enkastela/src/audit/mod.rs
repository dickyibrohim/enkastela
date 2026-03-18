//! Audit trail for cryptographic operations.
//!
//! Provides tamper-evident logging of all encryption, decryption, key management,
//! and data-access operations. Events are chained via HMAC-SHA256 to detect
//! deletion, reordering, or modification.
//!
//! # Modules
//!
//! - [`events`] — Audit event types and builder
//! - [`integrity`] — HMAC hash chain for tamper evidence
//! - [`logger`] — Async batched audit logger

pub mod events;
pub mod integrity;
pub mod logger;
