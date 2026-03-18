//! Field-level access control.
//!
//! Controls which roles can decrypt which fields. For example:
//! - Role "support" can decrypt `name` but not `ssn`
//! - Role "admin" can decrypt everything
//! - Role "analytics" cannot decrypt anything (only sees ciphertext)
//!
//! Policies are evaluated in O(1) time using precomputed bitmasks.

pub mod context;
pub mod policy;
