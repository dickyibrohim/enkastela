//! Type wrappers for encrypted field values.
//!
//! These types encode encryption intent at the type level, ensuring that
//! encryption mode mismatches are caught at compile time.

pub mod deterministic;
pub mod encrypted;
pub mod encrypted_json;
pub mod searchable;
pub mod traits;
