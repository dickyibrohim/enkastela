//! Shared test infrastructure for enkastela.
//!
//! Provides test utilities including:
//! - PostgreSQL testcontainers setup
//! - Test key material and fixtures
//! - Crypto-specific test assertions
//!
//! # Security
//!
//! This crate is `publish = false` and should NEVER be used in production.
//! It contains test-only key providers that are not suitable for real-world use.

// pub mod containers;
// pub mod fixtures;
// pub mod assertions;
