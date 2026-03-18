//! Storage layer for enkastela.
//!
//! - [`codec`] — Wire format v1 encode/decode
//! - [`migrations`] — SQL migrations with execution support
//! - [`pool`] — PostgreSQL connection pool with TLS enforcement
//! - [`repository`] — Key repository trait with in-memory and PostgreSQL implementations

pub mod codec;
pub mod migrations;
pub mod pool;
pub mod repository;
