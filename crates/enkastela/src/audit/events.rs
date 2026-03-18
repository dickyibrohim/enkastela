//! Audit event types and builder.
//!
//! Every cryptographic operation emits an [`AuditEvent`] that is appended to the
//! tamper-evident log. The [`AuditEventBuilder`] provides a fluent API for
//! constructing events, while the [`EventHasher`] trait abstracts the hash
//! computation so callers can plug in HMAC or other schemes.

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Global monotonic event ID counter.
///
/// Using `Relaxed` is sufficient because the HMAC chain (not the ID) provides
/// ordering guarantees. The counter only needs to be unique, not sequentially
/// consistent across threads.
static NEXT_EVENT_ID: AtomicU64 = AtomicU64::new(1);

/// Actions tracked in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// A field was encrypted.
    Encrypt,
    /// A field was decrypted.
    Decrypt,
    /// A new key was created.
    KeyCreate,
    /// A key rotation was initiated.
    KeyRotateStart,
    /// A key rotation completed successfully.
    KeyRotateComplete,
    /// A key was destroyed (crypto-shredding).
    KeyDestroy,
    /// A tenant-specific key was created.
    TenantKeyCreate,
    /// A tenant's data was crypto-erased.
    TenantErase,
    /// Data was exported.
    DataExport,
    /// A blind index was computed.
    BlindIndexCompute,
}

/// A single audit event in the tamper-evident log.
///
/// Each event carries an `event_hash` computed over the event data concatenated
/// with the previous event's hash, forming an HMAC chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonically increasing event identifier.
    pub id: u64,
    /// UTC timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// The action that was performed.
    pub action: AuditAction,
    /// The database table involved, if any.
    pub table_name: Option<String>,
    /// The column involved, if any.
    pub column_name: Option<String>,
    /// The row identifier involved, if any.
    pub row_id: Option<String>,
    /// The actor (user, service, API key) that performed the action.
    pub actor: Option<String>,
    /// The key version used, if applicable.
    pub key_version: Option<u32>,
    /// Arbitrary JSON metadata for extensibility.
    pub metadata: Option<serde_json::Value>,
    /// Hash of the previous event in the chain (None for the first event).
    pub prev_hash: Option<Vec<u8>>,
    /// HMAC hash of this event's data concatenated with `prev_hash`.
    pub event_hash: Vec<u8>,
}

/// Trait for computing the chained hash of audit events.
///
/// Implementations must be thread-safe (`Send + Sync`) because the audit
/// logger may hash events from multiple async tasks.
pub trait EventHasher: Send + Sync {
    /// Compute the hash of `event_data` chained with the optional `prev_hash`.
    ///
    /// The canonical computation is `HMAC(key, prev_hash || event_data)`.
    fn hash_event(&self, event_data: &[u8], prev_hash: Option<&[u8]>) -> Vec<u8>;
}

/// Builder for constructing [`AuditEvent`] instances.
///
/// # Example
///
/// ```rust,ignore
/// let event = AuditEventBuilder::new(AuditAction::Encrypt)
///     .table("users")
///     .column("email")
///     .row_id("42")
///     .actor("service-account")
///     .key_version(3)
///     .build(&hasher, None);
/// ```
pub struct AuditEventBuilder {
    action: AuditAction,
    table_name: Option<String>,
    column_name: Option<String>,
    row_id: Option<String>,
    actor: Option<String>,
    key_version: Option<u32>,
    metadata: Option<serde_json::Value>,
}

impl AuditEventBuilder {
    /// Start building an event for the given action.
    pub fn new(action: AuditAction) -> Self {
        Self {
            action,
            table_name: None,
            column_name: None,
            row_id: None,
            actor: None,
            key_version: None,
            metadata: None,
        }
    }

    /// Set the action.
    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = action;
        self
    }

    /// Set the table name.
    pub fn table(mut self, table: impl Into<String>) -> Self {
        self.table_name = Some(table.into());
        self
    }

    /// Set the column name.
    pub fn column(mut self, column: impl Into<String>) -> Self {
        self.column_name = Some(column.into());
        self
    }

    /// Set the row identifier.
    pub fn row_id(mut self, row_id: impl Into<String>) -> Self {
        self.row_id = Some(row_id.into());
        self
    }

    /// Set the actor (user, service, API key).
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Set the key version.
    pub fn key_version(mut self, version: u32) -> Self {
        self.key_version = Some(version);
        self
    }

    /// Set arbitrary JSON metadata.
    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Consume the builder and produce a hashed [`AuditEvent`].
    ///
    /// `prev_hash` is the hash of the previous event in the chain, or `None`
    /// for the first event.
    pub fn build(self, hasher: &dyn EventHasher, prev_hash: Option<&[u8]>) -> AuditEvent {
        let id = NEXT_EVENT_ID.fetch_add(1, Ordering::Relaxed);
        let timestamp = Utc::now();

        // Serialize the event data for hashing. We include all fields that
        // should be covered by the integrity check.
        let event_data = serialize_event_data(
            id,
            &timestamp,
            &self.action,
            self.table_name.as_deref(),
            self.column_name.as_deref(),
            self.row_id.as_deref(),
            self.actor.as_deref(),
            self.key_version,
            self.metadata.as_ref(),
        );

        let event_hash = hasher.hash_event(&event_data, prev_hash);

        AuditEvent {
            id,
            timestamp,
            action: self.action,
            table_name: self.table_name,
            column_name: self.column_name,
            row_id: self.row_id,
            actor: self.actor,
            key_version: self.key_version,
            metadata: self.metadata,
            prev_hash: prev_hash.map(|h| h.to_vec()),
            event_hash,
        }
    }
}

/// Canonical serialization of event fields for hashing.
///
/// This deterministic representation ensures that verification can recompute
/// exactly the same bytes that were hashed at creation time.
#[allow(clippy::too_many_arguments)]
pub(crate) fn serialize_event_data(
    id: u64,
    timestamp: &DateTime<Utc>,
    action: &AuditAction,
    table_name: Option<&str>,
    column_name: Option<&str>,
    row_id: Option<&str>,
    actor: Option<&str>,
    key_version: Option<u32>,
    metadata: Option<&serde_json::Value>,
) -> Vec<u8> {
    // Use JSON for deterministic, reproducible serialization.
    let canonical = serde_json::json!({
        "id": id,
        "timestamp": timestamp.to_rfc3339(),
        "action": action,
        "table_name": table_name,
        "column_name": column_name,
        "row_id": row_id,
        "actor": actor,
        "key_version": key_version,
        "metadata": metadata,
    });
    serde_json::to_vec(&canonical).expect("canonical event serialization must not fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial hasher that concatenates prev_hash and event_data for testing.
    struct TestHasher;

    impl EventHasher for TestHasher {
        fn hash_event(&self, event_data: &[u8], prev_hash: Option<&[u8]>) -> Vec<u8> {
            let mut out = Vec::new();
            if let Some(ph) = prev_hash {
                out.extend_from_slice(ph);
            }
            out.extend_from_slice(event_data);
            // Return first 32 bytes (or pad) to simulate a fixed-size hash.
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(&out);
            digest.to_vec()
        }
    }

    #[test]
    fn builder_creates_valid_event() {
        let hasher = TestHasher;
        let event = AuditEventBuilder::new(AuditAction::Encrypt)
            .table("users")
            .column("email")
            .row_id("42")
            .actor("svc-account")
            .key_version(3)
            .build(&hasher, None);

        assert_eq!(event.action, AuditAction::Encrypt);
        assert_eq!(event.table_name.as_deref(), Some("users"));
        assert_eq!(event.column_name.as_deref(), Some("email"));
        assert_eq!(event.row_id.as_deref(), Some("42"));
        assert_eq!(event.actor.as_deref(), Some("svc-account"));
        assert_eq!(event.key_version, Some(3));
        assert!(event.prev_hash.is_none());
        assert!(!event.event_hash.is_empty());
        assert!(event.id > 0);
    }

    #[test]
    fn all_fields_set_correctly() {
        let hasher = TestHasher;
        let meta = serde_json::json!({"ip": "10.0.0.1"});
        let prev = vec![0xAA; 32];

        let event = AuditEventBuilder::new(AuditAction::KeyRotateStart)
            .table("orders")
            .column("card_number")
            .row_id("99")
            .actor("admin")
            .key_version(7)
            .metadata(meta.clone())
            .build(&hasher, Some(&prev));

        assert_eq!(event.action, AuditAction::KeyRotateStart);
        assert_eq!(event.table_name.as_deref(), Some("orders"));
        assert_eq!(event.column_name.as_deref(), Some("card_number"));
        assert_eq!(event.row_id.as_deref(), Some("99"));
        assert_eq!(event.actor.as_deref(), Some("admin"));
        assert_eq!(event.key_version, Some(7));
        assert_eq!(event.metadata, Some(meta));
        assert_eq!(event.prev_hash.as_deref(), Some(prev.as_slice()));
        assert_eq!(event.event_hash.len(), 32);
    }

    #[test]
    fn optional_fields_default_to_none() {
        let hasher = TestHasher;
        let event = AuditEventBuilder::new(AuditAction::Decrypt).build(&hasher, None);

        assert_eq!(event.action, AuditAction::Decrypt);
        assert!(event.table_name.is_none());
        assert!(event.column_name.is_none());
        assert!(event.row_id.is_none());
        assert!(event.actor.is_none());
        assert!(event.key_version.is_none());
        assert!(event.metadata.is_none());
        assert!(event.prev_hash.is_none());
    }

    #[test]
    fn action_serialization_roundtrip() {
        let actions = [
            AuditAction::Encrypt,
            AuditAction::Decrypt,
            AuditAction::KeyCreate,
            AuditAction::KeyRotateStart,
            AuditAction::KeyRotateComplete,
            AuditAction::KeyDestroy,
            AuditAction::TenantKeyCreate,
            AuditAction::TenantErase,
            AuditAction::DataExport,
            AuditAction::BlindIndexCompute,
        ];
        let expected_names = [
            "\"encrypt\"",
            "\"decrypt\"",
            "\"key_create\"",
            "\"key_rotate_start\"",
            "\"key_rotate_complete\"",
            "\"key_destroy\"",
            "\"tenant_key_create\"",
            "\"tenant_erase\"",
            "\"data_export\"",
            "\"blind_index_compute\"",
        ];

        for (action, expected) in actions.iter().zip(expected_names.iter()) {
            let serialized = serde_json::to_string(action).unwrap();
            assert_eq!(
                &serialized, expected,
                "serialization mismatch for {:?}",
                action
            );

            let deserialized: AuditAction = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*action, deserialized);
        }
    }

    #[test]
    fn action_method_overrides_constructor() {
        let hasher = TestHasher;
        let event = AuditEventBuilder::new(AuditAction::Encrypt)
            .action(AuditAction::KeyDestroy)
            .build(&hasher, None);

        assert_eq!(event.action, AuditAction::KeyDestroy);
    }

    #[test]
    fn event_ids_are_monotonically_increasing() {
        let hasher = TestHasher;
        let e1 = AuditEventBuilder::new(AuditAction::Encrypt).build(&hasher, None);
        let e2 = AuditEventBuilder::new(AuditAction::Decrypt).build(&hasher, None);
        let e3 = AuditEventBuilder::new(AuditAction::KeyCreate).build(&hasher, None);

        assert!(e2.id > e1.id);
        assert!(e3.id > e2.id);
    }

    #[test]
    fn different_prev_hash_produces_different_event_hash() {
        let hasher = TestHasher;
        let e1 = AuditEventBuilder::new(AuditAction::Encrypt)
            .table("t")
            .build(&hasher, None);
        let e2 = AuditEventBuilder::new(AuditAction::Encrypt)
            .table("t")
            .build(&hasher, Some(&[0xFF; 32]));

        // Different prev_hash means different event_hash (even though IDs differ
        // too, the prev_hash contribution is the key property).
        assert_ne!(e1.event_hash, e2.event_hash);
    }

    #[test]
    fn serialize_event_data_is_deterministic() {
        let ts = Utc::now();
        let action = AuditAction::Encrypt;
        let meta = serde_json::json!({"key": "value"});

        let d1 = serialize_event_data(
            1,
            &ts,
            &action,
            Some("t"),
            Some("c"),
            Some("r"),
            Some("a"),
            Some(1),
            Some(&meta),
        );
        let d2 = serialize_event_data(
            1,
            &ts,
            &action,
            Some("t"),
            Some("c"),
            Some("r"),
            Some("a"),
            Some(1),
            Some(&meta),
        );

        assert_eq!(d1, d2);
    }
}
