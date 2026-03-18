//! Poison record management — create, store, and identify canary records.

use std::collections::HashSet;
use std::sync::RwLock;

/// A poison record identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoisonRecord {
    /// Table containing the poison record.
    pub table: String,
    /// Column containing the poison value.
    pub column: String,
    /// Row identifier (e.g., primary key value).
    pub row_id: String,
    /// The canary plaintext value (for identification).
    pub canary_value: Vec<u8>,
}

impl PoisonRecord {
    /// Creates a new poison record descriptor.
    pub fn new(table: &str, column: &str, row_id: &str, canary_value: &[u8]) -> Self {
        Self {
            table: table.to_string(),
            column: column.to_string(),
            row_id: row_id.to_string(),
            canary_value: canary_value.to_vec(),
        }
    }

    /// Returns a unique key for this poison record.
    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.table, self.column, self.row_id)
    }
}

/// Registry of planted poison records.
pub struct PoisonRegistry {
    records: RwLock<HashSet<String>>,
    canaries: RwLock<Vec<PoisonRecord>>,
}

impl PoisonRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashSet::new()),
            canaries: RwLock::new(Vec::new()),
        }
    }

    /// Registers a poison record.
    pub fn register(&self, record: PoisonRecord) {
        let key = record.key();
        self.records.write().unwrap().insert(key);
        self.canaries.write().unwrap().push(record);
    }

    /// Checks if a given table/column/row combination is a poison record.
    pub fn is_poison(&self, table: &str, column: &str, row_id: &str) -> bool {
        let key = format!("{table}:{column}:{row_id}");
        self.records.read().unwrap().contains(&key)
    }

    /// Returns the number of planted poison records.
    pub fn count(&self) -> usize {
        self.records.read().unwrap().len()
    }

    /// Returns all registered poison records.
    pub fn all_records(&self) -> Vec<PoisonRecord> {
        self.canaries.read().unwrap().clone()
    }
}

impl Default for PoisonRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_detect() {
        let registry = PoisonRegistry::new();
        let record = PoisonRecord::new("users", "email", "canary-001", b"trap@internal.test");
        registry.register(record);

        assert!(registry.is_poison("users", "email", "canary-001"));
        assert!(!registry.is_poison("users", "email", "real-user"));
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn multiple_records() {
        let registry = PoisonRegistry::new();
        registry.register(PoisonRecord::new("users", "email", "c1", b"a"));
        registry.register(PoisonRecord::new("users", "ssn", "c2", b"b"));
        registry.register(PoisonRecord::new("orders", "address", "c3", b"c"));

        assert!(registry.is_poison("users", "email", "c1"));
        assert!(registry.is_poison("users", "ssn", "c2"));
        assert!(registry.is_poison("orders", "address", "c3"));
        assert_eq!(registry.count(), 3);
    }

    #[test]
    fn all_records_returns_all() {
        let registry = PoisonRegistry::new();
        registry.register(PoisonRecord::new("t", "c", "r1", b"v1"));
        registry.register(PoisonRecord::new("t", "c", "r2", b"v2"));

        let all = registry.all_records();
        assert_eq!(all.len(), 2);
    }
}
