//! HMAC-SHA256 hash chain for tamper-evident audit logs.
//!
//! Each audit event is hashed with HMAC-SHA256 over the concatenation of the
//! previous event's hash and the current event's serialized data. This forms a
//! hash chain analogous to a blockchain: any insertion, deletion, reordering,
//! or modification of events is detectable.
//!
//! # Security
//!
//! - The HMAC key must be stored separately from the audit log itself.
//! - Hash comparisons use constant-time equality to prevent timing attacks.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::crypto::constant_time::ct_eq;
use crate::crypto::secret::SecretKey;
use crate::error::Error;

use super::events::{serialize_event_data, AuditEvent, EventHasher};

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 based event hasher for audit integrity.
///
/// Computes `HMAC-SHA256(key, prev_hash || event_data)` for each event,
/// creating a hash chain that provides tamper evidence.
pub struct HmacEventHasher {
    key: SecretKey,
}

impl HmacEventHasher {
    /// Create a new hasher with the given HMAC key.
    ///
    /// The key should be at least 256 bits and stored separately from the
    /// audit log to prevent an attacker who compromises the log from
    /// recomputing valid hashes.
    pub fn new(key: SecretKey) -> Self {
        Self { key }
    }
}

impl EventHasher for HmacEventHasher {
    fn hash_event(&self, event_data: &[u8], prev_hash: Option<&[u8]>) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(self.key.as_bytes()).expect("HMAC accepts any key size");

        // Chain: include the previous hash first for ordering guarantee
        if let Some(ph) = prev_hash {
            mac.update(ph);
        }
        mac.update(event_data);

        mac.finalize().into_bytes().to_vec()
    }
}

/// Verifies the integrity of a sequence of audit events.
///
/// Walks the chain from the first event to the last, recomputing each hash
/// and comparing it (in constant time) against the stored `event_hash`.
///
/// # Returns
///
/// - `Ok(true)` if all hashes match and the chain is intact.
/// - `Ok(false)` if any hash mismatch is detected (tampered, deleted, or reordered).
/// - `Err(_)` if an internal error occurs.
///
/// An empty chain is considered valid.
pub fn verify_chain(key: &SecretKey, events: &[AuditEvent]) -> Result<bool, Error> {
    if events.is_empty() {
        return Ok(true);
    }

    let hasher = HmacEventHasher::new(SecretKey::from_bytes(*key.as_bytes()));
    let mut expected_prev_hash: Option<Vec<u8>> = None;

    for event in events {
        // Verify the prev_hash pointer matches what we expect
        match (&expected_prev_hash, &event.prev_hash) {
            (None, None) => {}
            (Some(expected), Some(actual)) => {
                if !ct_eq(expected, actual) {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }

        // Recompute the hash from the event's data fields
        let event_data = serialize_event_data(
            event.id,
            &event.timestamp,
            &event.action,
            event.table_name.as_deref(),
            event.column_name.as_deref(),
            event.row_id.as_deref(),
            event.actor.as_deref(),
            event.key_version,
            event.metadata.as_ref(),
        );

        let recomputed = hasher.hash_event(&event_data, expected_prev_hash.as_deref());

        if !ct_eq(&recomputed, &event.event_hash) {
            return Ok(false);
        }

        expected_prev_hash = Some(event.event_hash.clone());
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::{AuditAction, AuditEventBuilder};

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    /// Build a chain of events using the HMAC hasher.
    fn build_chain(key: &SecretKey, count: usize) -> Vec<AuditEvent> {
        let hasher = HmacEventHasher::new(SecretKey::from_bytes(*key.as_bytes()));
        let mut events = Vec::with_capacity(count);
        let mut prev_hash: Option<Vec<u8>> = None;

        let actions = [
            AuditAction::Encrypt,
            AuditAction::Decrypt,
            AuditAction::KeyCreate,
            AuditAction::KeyRotateStart,
            AuditAction::KeyRotateComplete,
        ];

        for i in 0..count {
            let action = actions[i % actions.len()];
            let event = AuditEventBuilder::new(action)
                .table(format!("table_{}", i))
                .column(format!("col_{}", i))
                .row_id(format!("{}", i))
                .actor("test-actor")
                .key_version(1)
                .build(&hasher, prev_hash.as_deref());

            prev_hash = Some(event.event_hash.clone());
            events.push(event);
        }

        events
    }

    #[test]
    fn hash_chain_computation() {
        let key = test_key();
        let hasher = HmacEventHasher::new(SecretKey::from_bytes(*key.as_bytes()));

        let e1 = AuditEventBuilder::new(AuditAction::Encrypt)
            .table("users")
            .build(&hasher, None);

        assert!(e1.prev_hash.is_none());
        assert_eq!(e1.event_hash.len(), 32);

        let e2 = AuditEventBuilder::new(AuditAction::Decrypt)
            .table("users")
            .build(&hasher, Some(&e1.event_hash));

        assert_eq!(e2.prev_hash.as_deref(), Some(e1.event_hash.as_slice()));
        assert_eq!(e2.event_hash.len(), 32);
        assert_ne!(e1.event_hash, e2.event_hash);
    }

    #[test]
    fn chain_verification_succeeds_for_valid_chain() {
        let key = test_key();
        let events = build_chain(&key, 10);

        assert!(verify_chain(&key, &events).unwrap());
    }

    #[test]
    fn chain_verification_fails_when_event_is_tampered() {
        let key = test_key();
        let mut events = build_chain(&key, 5);

        // Tamper with the table name of the third event
        events[2].table_name = Some("tampered_table".to_string());

        assert!(!verify_chain(&key, &events).unwrap());
    }

    #[test]
    fn chain_verification_fails_when_hash_is_tampered() {
        let key = test_key();
        let mut events = build_chain(&key, 5);

        // Tamper with the hash of the second event
        events[1].event_hash = vec![0xFF; 32];

        assert!(!verify_chain(&key, &events).unwrap());
    }

    #[test]
    fn chain_verification_fails_when_event_is_deleted() {
        let key = test_key();
        let mut events = build_chain(&key, 5);

        // Delete the middle event (index 2)
        events.remove(2);

        // Now event at index 2 (originally index 3) has prev_hash pointing to
        // event 2's hash, but event at index 1 has a different hash.
        assert!(!verify_chain(&key, &events).unwrap());
    }

    #[test]
    fn chain_verification_fails_when_events_are_reordered() {
        let key = test_key();
        let mut events = build_chain(&key, 5);

        // Swap events 2 and 3
        events.swap(2, 3);

        assert!(!verify_chain(&key, &events).unwrap());
    }

    #[test]
    fn empty_chain_is_valid() {
        let key = test_key();
        assert!(verify_chain(&key, &[]).unwrap());
    }

    #[test]
    fn single_event_chain_is_valid() {
        let key = test_key();
        let events = build_chain(&key, 1);
        assert!(verify_chain(&key, &events).unwrap());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = test_key();
        let events = build_chain(&key, 5);

        let wrong_key = SecretKey::from_bytes([0xFF; 32]);
        assert!(!verify_chain(&wrong_key, &events).unwrap());
    }

    #[test]
    fn chain_verification_fails_when_prev_hash_is_tampered() {
        let key = test_key();
        let mut events = build_chain(&key, 5);

        // Tamper with prev_hash of the third event
        events[2].prev_hash = Some(vec![0x00; 32]);

        assert!(!verify_chain(&key, &events).unwrap());
    }

    #[test]
    fn chain_verification_fails_when_first_event_has_prev_hash() {
        let key = test_key();
        let mut events = build_chain(&key, 3);

        // First event should have no prev_hash; inject one
        events[0].prev_hash = Some(vec![0xDE; 32]);

        assert!(!verify_chain(&key, &events).unwrap());
    }
}
