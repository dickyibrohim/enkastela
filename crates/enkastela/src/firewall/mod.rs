//! SQL Firewall — detect queries that bypass field encryption.
//!
//! Parses SQL queries and flags potential encryption violations:
//!
//! - `SELECT` directly reading encrypted columns without Vault decryption
//! - `INSERT` with plaintext values into encrypted columns
//! - `WHERE` comparing encrypted columns with plaintext literals
//! - `JOIN` on encrypted columns (would never match)
//!
//! # Feature
//!
//! This module requires the `firewall` feature flag.

#[cfg(feature = "firewall")]
pub mod analyzer;
#[cfg(feature = "firewall")]
pub mod policy;
