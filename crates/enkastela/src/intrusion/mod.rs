//! Intrusion detection via poison records (honeypots).
//!
//! Plant fake encrypted records in the database. If anyone decrypts them,
//! an alert is triggered — indicating unauthorized access or a data breach.
//!
//! # How It Works
//!
//! 1. `plant_poison()` encrypts a canary value and stores it in the database
//! 2. A `PoisonDetector` wraps the Vault's decrypt path
//! 3. If a poison record is decrypted, the detector fires an alert
//!
//! This is conceptually similar to Acra's poison records, but integrated
//! directly into the Vault rather than requiring a separate proxy.

pub mod detector;
pub mod poison;
