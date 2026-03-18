//! Data portability export for GDPR Article 20.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single exported record (decrypted for portability).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub table: String,
    pub column: String,
    pub row_id: Option<String>,
    pub value: Vec<u8>,
}

/// Complete data export for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExport {
    pub tenant_id: String,
    pub exported_at: DateTime<Utc>,
    pub records: Vec<ExportRecord>,
    pub record_count: usize,
}

impl DataExport {
    /// Creates a new empty export.
    pub fn new(tenant_id: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            exported_at: Utc::now(),
            records: Vec::new(),
            record_count: 0,
        }
    }

    /// Adds a record to the export.
    pub fn add_record(&mut self, table: &str, column: &str, row_id: Option<&str>, value: Vec<u8>) {
        self.records.push(ExportRecord {
            table: table.to_string(),
            column: column.to_string(),
            row_id: row_id.map(|s| s.to_string()),
            value,
        });
        self.record_count = self.records.len();
    }

    /// Serializes the export to JSON.
    pub fn to_json(&self) -> Result<String, crate::error::Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::Error::Config(format!("export serialization failed: {e}")))
    }

    /// Returns true if the export has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_populate_export() {
        let mut export = DataExport::new("tenant-1");
        assert_eq!(export.tenant_id, "tenant-1");
        assert!(export.is_empty());

        export.add_record(
            "users",
            "email",
            Some("row-1"),
            b"alice@example.com".to_vec(),
        );
        export.add_record("users", "phone", Some("row-1"), b"+1234567890".to_vec());

        assert!(!export.is_empty());
        assert_eq!(export.record_count, 2);
        assert_eq!(export.records.len(), 2);
        assert_eq!(export.records[0].table, "users");
        assert_eq!(export.records[0].column, "email");
        assert_eq!(export.records[0].row_id.as_deref(), Some("row-1"));
        assert_eq!(export.records[0].value, b"alice@example.com");
    }

    #[test]
    fn json_serialization_roundtrip() {
        let mut export = DataExport::new("tenant-1");
        export.add_record(
            "users",
            "email",
            Some("row-1"),
            b"alice@example.com".to_vec(),
        );
        export.add_record("orders", "address", None, b"123 Main St".to_vec());

        let json = export.to_json().unwrap();
        let deserialized: DataExport = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tenant_id, "tenant-1");
        assert_eq!(deserialized.record_count, 2);
        assert_eq!(deserialized.records.len(), 2);
        assert_eq!(deserialized.records[0].table, "users");
        assert_eq!(deserialized.records[0].column, "email");
        assert_eq!(deserialized.records[0].value, b"alice@example.com");
        assert_eq!(deserialized.records[1].table, "orders");
        assert_eq!(deserialized.records[1].row_id, None);
    }

    #[test]
    fn empty_export() {
        let export = DataExport::new("tenant-1");
        assert!(export.is_empty());
        assert_eq!(export.record_count, 0);

        let json = export.to_json().unwrap();
        let deserialized: DataExport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_empty());
    }

    #[test]
    fn record_count_accurate() {
        let mut export = DataExport::new("tenant-1");
        assert_eq!(export.record_count, 0);

        for i in 0..5 {
            export.add_record(
                "users",
                "email",
                Some(&format!("row-{i}")),
                format!("user{i}@example.com").into_bytes(),
            );
        }

        assert_eq!(export.record_count, 5);
        assert_eq!(export.records.len(), 5);
    }

    #[test]
    fn add_record_without_row_id() {
        let mut export = DataExport::new("tenant-1");
        export.add_record("logs", "message", None, b"some log entry".to_vec());

        assert_eq!(export.records[0].row_id, None);
        assert_eq!(export.record_count, 1);
    }
}
