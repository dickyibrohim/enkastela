//! Key rotation progress tracking.

use chrono::{DateTime, Utc};

/// Tracks the progress of a key rotation operation.
#[derive(Debug, Clone)]
pub struct RotationProgress {
    pub table: String,
    pub from_version: u32,
    pub to_version: u32,
    pub total_rows: Option<u64>,
    pub processed_rows: u64,
    pub last_processed_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: RotationStatus,
}

/// Status of a key rotation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStatus {
    InProgress,
    Completed,
    Failed,
    Paused,
}

impl RotationProgress {
    /// Creates a new rotation progress tracker.
    pub fn new(table: &str, from_version: u32, to_version: u32) -> Self {
        Self {
            table: table.to_string(),
            from_version,
            to_version,
            total_rows: None,
            processed_rows: 0,
            last_processed_id: None,
            started_at: Utc::now(),
            completed_at: None,
            status: RotationStatus::InProgress,
        }
    }

    /// Advances progress after processing a batch.
    pub fn advance(&mut self, rows_in_batch: u64, last_id: Option<String>) {
        self.processed_rows += rows_in_batch;
        if last_id.is_some() {
            self.last_processed_id = last_id;
        }
    }

    /// Marks the rotation as complete.
    pub fn complete(&mut self) {
        self.status = RotationStatus::Completed;
        self.completed_at = Some(Utc::now());
    }

    /// Marks the rotation as failed.
    pub fn fail(&mut self) {
        self.status = RotationStatus::Failed;
        self.completed_at = Some(Utc::now());
    }

    /// Returns the completion percentage (0.0 to 100.0).
    pub fn percentage(&self) -> Option<f64> {
        self.total_rows.map(|total| {
            if total == 0 {
                100.0
            } else {
                (self.processed_rows as f64 / total as f64) * 100.0
            }
        })
    }

    /// Returns true if the rotation is finished (completed or failed).
    pub fn is_finished(&self) -> bool {
        matches!(
            self.status,
            RotationStatus::Completed | RotationStatus::Failed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_progress_starts_in_progress() {
        let p = RotationProgress::new("users", 1, 2);
        assert_eq!(p.table, "users");
        assert_eq!(p.from_version, 1);
        assert_eq!(p.to_version, 2);
        assert_eq!(p.processed_rows, 0);
        assert_eq!(p.status, RotationStatus::InProgress);
        assert!(p.completed_at.is_none());
        assert!(p.last_processed_id.is_none());
        assert!(!p.is_finished());
    }

    #[test]
    fn advance_updates_processed_rows() {
        let mut p = RotationProgress::new("users", 1, 2);
        p.total_rows = Some(1000);

        p.advance(100, Some("row-100".to_string()));
        assert_eq!(p.processed_rows, 100);
        assert_eq!(p.last_processed_id.as_deref(), Some("row-100"));

        p.advance(200, Some("row-300".to_string()));
        assert_eq!(p.processed_rows, 300);
        assert_eq!(p.last_processed_id.as_deref(), Some("row-300"));
    }

    #[test]
    fn advance_with_none_last_id_preserves_previous() {
        let mut p = RotationProgress::new("users", 1, 2);
        p.advance(50, Some("row-50".to_string()));
        p.advance(50, None);
        assert_eq!(p.processed_rows, 100);
        assert_eq!(p.last_processed_id.as_deref(), Some("row-50"));
    }

    #[test]
    fn complete_marks_finished() {
        let mut p = RotationProgress::new("users", 1, 2);
        p.complete();
        assert_eq!(p.status, RotationStatus::Completed);
        assert!(p.completed_at.is_some());
        assert!(p.is_finished());
    }

    #[test]
    fn fail_marks_finished() {
        let mut p = RotationProgress::new("users", 1, 2);
        p.fail();
        assert_eq!(p.status, RotationStatus::Failed);
        assert!(p.completed_at.is_some());
        assert!(p.is_finished());
    }

    #[test]
    fn percentage_with_total() {
        let mut p = RotationProgress::new("users", 1, 2);
        p.total_rows = Some(200);
        p.advance(50, None);
        let pct = p.percentage().unwrap();
        assert!((pct - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn percentage_without_total_returns_none() {
        let p = RotationProgress::new("users", 1, 2);
        assert!(p.percentage().is_none());
    }

    #[test]
    fn percentage_with_zero_total_returns_100() {
        let mut p = RotationProgress::new("users", 1, 2);
        p.total_rows = Some(0);
        let pct = p.percentage().unwrap();
        assert!((pct - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn is_finished_false_for_in_progress_and_paused() {
        let mut p = RotationProgress::new("users", 1, 2);
        assert!(!p.is_finished());

        p.status = RotationStatus::Paused;
        assert!(!p.is_finished());
    }
}
