//! Automatic re-encryption pipeline for key rotation.
//!
//! Provides cursor-based, resumable re-encryption of database rows. When a
//! key is rotated, existing ciphertexts need to be re-encrypted with the new
//! key version. This module handles that process:
//!
//! 1. Read a batch of rows from the target table
//! 2. Decrypt each field with the old key version
//! 3. Re-encrypt with the new key version
//! 4. Update the row in the database
//! 5. Record progress for resumability
//!
//! # Resumability
//!
//! Progress is tracked via cursor position. If the process crashes, it can
//! resume from the last recorded cursor without re-processing already-rotated
//! rows.

use std::fmt;

/// Configuration for a re-encryption pipeline run.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Table to re-encrypt.
    pub table: String,
    /// Columns containing encrypted data.
    pub columns: Vec<String>,
    /// Primary key column for cursor-based pagination.
    pub pk_column: String,
    /// Number of rows per batch.
    pub batch_size: usize,
    /// Source key version (decrypt with this).
    pub from_version: u32,
    /// Target key version (encrypt with this).
    pub to_version: u32,
}

impl PipelineConfig {
    /// Creates a new pipeline configuration.
    pub fn new(table: &str, columns: Vec<String>, from_version: u32, to_version: u32) -> Self {
        Self {
            table: table.to_string(),
            columns,
            pk_column: "id".to_string(),
            batch_size: 500,
            from_version,
            to_version,
        }
    }

    /// Sets the primary key column name.
    pub fn pk_column(mut self, pk: &str) -> Self {
        self.pk_column = pk.to_string();
        self
    }

    /// Sets the batch size.
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = if size == 0 { 500 } else { size };
        self
    }
}

/// Progress state for a re-encryption run.
#[derive(Debug, Clone)]
pub struct PipelineProgress {
    /// Last processed cursor value (primary key).
    pub last_cursor: Option<String>,
    /// Number of rows processed so far.
    pub rows_processed: u64,
    /// Number of rows that failed to re-encrypt.
    pub rows_failed: u64,
    /// Total rows to process (if known).
    pub total_rows: Option<u64>,
    /// Current status.
    pub status: PipelineStatus,
}

impl PipelineProgress {
    /// Creates a fresh progress tracker.
    pub fn new() -> Self {
        Self {
            last_cursor: None,
            rows_processed: 0,
            rows_failed: 0,
            total_rows: None,
            status: PipelineStatus::Pending,
        }
    }

    /// Returns the percentage complete, if total is known.
    pub fn percentage(&self) -> Option<f64> {
        self.total_rows.map(|total| {
            if total == 0 {
                100.0
            } else {
                (self.rows_processed as f64 / total as f64) * 100.0
            }
        })
    }

    /// Returns whether the pipeline has completed (success or failure).
    pub fn is_finished(&self) -> bool {
        matches!(
            self.status,
            PipelineStatus::Completed | PipelineStatus::Failed(_)
        )
    }
}

impl Default for PipelineProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Status of a re-encryption pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineStatus {
    /// Not yet started.
    Pending,
    /// Currently processing rows.
    Running,
    /// Paused (can be resumed).
    Paused,
    /// Successfully completed all rows.
    Completed,
    /// Failed with an error message.
    Failed(String),
}

impl fmt::Display for PipelineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineStatus::Pending => write!(f, "pending"),
            PipelineStatus::Running => write!(f, "running"),
            PipelineStatus::Paused => write!(f, "paused"),
            PipelineStatus::Completed => write!(f, "completed"),
            PipelineStatus::Failed(e) => write!(f, "failed: {}", e),
        }
    }
}

/// Result of processing a single batch.
#[derive(Debug)]
pub struct BatchResult {
    /// Number of rows successfully re-encrypted.
    pub success_count: u64,
    /// Number of rows that failed.
    pub failure_count: u64,
    /// Cursor value of the last processed row.
    pub last_cursor: Option<String>,
    /// Whether this was the final batch.
    pub is_last: bool,
}

/// A re-encryption pipeline that processes rows in batches.
///
/// # Usage
///
/// ```rust,no_run
/// use enkastela::rotation::pipeline::{PipelineConfig, ReEncryptionPipeline};
///
/// # async fn example() -> Result<(), enkastela::Error> {
/// let config = PipelineConfig::new("users", vec!["email".into(), "ssn".into()], 1, 2);
/// let mut pipeline = ReEncryptionPipeline::new(config);
///
/// // The pipeline tracks progress and can be resumed
/// assert!(!pipeline.progress().is_finished());
/// # Ok(())
/// # }
/// ```
pub struct ReEncryptionPipeline {
    config: PipelineConfig,
    progress: PipelineProgress,
}

impl ReEncryptionPipeline {
    /// Creates a new re-encryption pipeline.
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            progress: PipelineProgress::new(),
        }
    }

    /// Creates a pipeline resuming from a previous progress state.
    pub fn resume(config: PipelineConfig, progress: PipelineProgress) -> Self {
        Self { config, progress }
    }

    /// Returns the current progress.
    pub fn progress(&self) -> &PipelineProgress {
        &self.progress
    }

    /// Returns the pipeline configuration.
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Records a successful batch result.
    pub fn record_batch(&mut self, result: BatchResult) {
        self.progress.rows_processed += result.success_count;
        self.progress.rows_failed += result.failure_count;
        if let Some(cursor) = result.last_cursor {
            self.progress.last_cursor = Some(cursor);
        }
        if result.is_last {
            self.progress.status = PipelineStatus::Completed;
        } else {
            self.progress.status = PipelineStatus::Running;
        }
    }

    /// Marks the pipeline as paused (can be resumed later).
    pub fn pause(&mut self) {
        if matches!(self.progress.status, PipelineStatus::Running) {
            self.progress.status = PipelineStatus::Paused;
        }
    }

    /// Marks the pipeline as failed.
    pub fn fail(&mut self, reason: &str) {
        self.progress.status = PipelineStatus::Failed(reason.to_string());
    }

    /// Sets the total row count for progress tracking.
    pub fn set_total_rows(&mut self, total: u64) {
        self.progress.total_rows = Some(total);
    }

    /// Generates the SQL query for fetching the next batch of rows.
    ///
    /// Returns a parameterized query with `$1` as the cursor parameter
    /// and `$2` as the limit.
    pub fn next_batch_query(&self) -> String {
        let columns = std::iter::once(self.config.pk_column.as_str())
            .chain(self.config.columns.iter().map(|s| s.as_str()))
            .collect::<Vec<_>>()
            .join(", ");

        match &self.progress.last_cursor {
            Some(_) => {
                format!(
                    "SELECT {} FROM {} WHERE {} > $1 ORDER BY {} ASC LIMIT $2",
                    columns, self.config.table, self.config.pk_column, self.config.pk_column
                )
            }
            None => {
                format!(
                    "SELECT {} FROM {} ORDER BY {} ASC LIMIT $1",
                    columns, self.config.table, self.config.pk_column
                )
            }
        }
    }

    /// Generates the SQL for updating a single row's encrypted columns.
    pub fn update_query(&self) -> String {
        let set_clauses: Vec<String> = self
            .config
            .columns
            .iter()
            .enumerate()
            .map(|(i, col)| format!("{} = ${}", col, i + 2))
            .collect();

        format!(
            "UPDATE {} SET {} WHERE {} = $1",
            self.config.table,
            set_clauses.join(", "),
            self.config.pk_column
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_progress_new() {
        let progress = PipelineProgress::new();
        assert_eq!(progress.rows_processed, 0);
        assert_eq!(progress.rows_failed, 0);
        assert!(progress.last_cursor.is_none());
        assert!(!progress.is_finished());
    }

    #[test]
    fn pipeline_progress_percentage() {
        let mut progress = PipelineProgress::new();
        progress.total_rows = Some(1000);
        progress.rows_processed = 250;
        assert!((progress.percentage().unwrap() - 25.0).abs() < 0.01);
    }

    #[test]
    fn pipeline_progress_percentage_zero_total() {
        let mut progress = PipelineProgress::new();
        progress.total_rows = Some(0);
        assert!((progress.percentage().unwrap() - 100.0).abs() < 0.01);
    }

    #[test]
    fn pipeline_progress_percentage_unknown_total() {
        let progress = PipelineProgress::new();
        assert!(progress.percentage().is_none());
    }

    #[test]
    fn pipeline_config_builder() {
        let config = PipelineConfig::new("users", vec!["email".into()], 1, 2)
            .pk_column("user_id")
            .batch_size(100);
        assert_eq!(config.table, "users");
        assert_eq!(config.pk_column, "user_id");
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.from_version, 1);
        assert_eq!(config.to_version, 2);
    }

    #[test]
    fn pipeline_record_batch() {
        let config = PipelineConfig::new("t", vec!["c".into()], 1, 2);
        let mut pipeline = ReEncryptionPipeline::new(config);

        pipeline.record_batch(BatchResult {
            success_count: 100,
            failure_count: 2,
            last_cursor: Some("abc-123".into()),
            is_last: false,
        });

        assert_eq!(pipeline.progress().rows_processed, 100);
        assert_eq!(pipeline.progress().rows_failed, 2);
        assert_eq!(pipeline.progress().last_cursor.as_deref(), Some("abc-123"));
        assert!(!pipeline.progress().is_finished());
    }

    #[test]
    fn pipeline_complete() {
        let config = PipelineConfig::new("t", vec!["c".into()], 1, 2);
        let mut pipeline = ReEncryptionPipeline::new(config);

        pipeline.record_batch(BatchResult {
            success_count: 50,
            failure_count: 0,
            last_cursor: Some("final".into()),
            is_last: true,
        });

        assert!(pipeline.progress().is_finished());
        assert!(matches!(
            pipeline.progress().status,
            PipelineStatus::Completed
        ));
    }

    #[test]
    fn pipeline_pause_and_resume() {
        let config = PipelineConfig::new("t", vec!["c".into()], 1, 2);
        let mut pipeline = ReEncryptionPipeline::new(config.clone());

        pipeline.record_batch(BatchResult {
            success_count: 50,
            failure_count: 0,
            last_cursor: Some("cursor-50".into()),
            is_last: false,
        });

        pipeline.pause();
        assert!(matches!(pipeline.progress().status, PipelineStatus::Paused));

        // Resume from progress
        let resumed = ReEncryptionPipeline::resume(config, pipeline.progress.clone());
        assert_eq!(resumed.progress().rows_processed, 50);
        assert_eq!(resumed.progress().last_cursor.as_deref(), Some("cursor-50"));
    }

    #[test]
    fn pipeline_fail() {
        let config = PipelineConfig::new("t", vec!["c".into()], 1, 2);
        let mut pipeline = ReEncryptionPipeline::new(config);

        pipeline.fail("connection lost");
        assert!(pipeline.progress().is_finished());
        assert!(matches!(
            pipeline.progress().status,
            PipelineStatus::Failed(_)
        ));
    }

    #[test]
    fn pipeline_next_batch_query_initial() {
        let config = PipelineConfig::new("users", vec!["email".into(), "ssn".into()], 1, 2);
        let pipeline = ReEncryptionPipeline::new(config);

        let query = pipeline.next_batch_query();
        assert!(query.contains("SELECT id, email, ssn FROM users"));
        assert!(query.contains("ORDER BY id ASC"));
        assert!(query.contains("LIMIT $1"));
    }

    #[test]
    fn pipeline_next_batch_query_with_cursor() {
        let config = PipelineConfig::new("users", vec!["email".into()], 1, 2);
        let mut pipeline = ReEncryptionPipeline::new(config);
        pipeline.progress.last_cursor = Some("abc".into());

        let query = pipeline.next_batch_query();
        assert!(query.contains("WHERE id > $1"));
        assert!(query.contains("LIMIT $2"));
    }

    #[test]
    fn pipeline_update_query() {
        let config = PipelineConfig::new("users", vec!["email".into(), "ssn".into()], 1, 2);
        let pipeline = ReEncryptionPipeline::new(config);

        let query = pipeline.update_query();
        assert_eq!(query, "UPDATE users SET email = $2, ssn = $3 WHERE id = $1");
    }

    #[test]
    fn pipeline_status_display() {
        assert_eq!(format!("{}", PipelineStatus::Pending), "pending");
        assert_eq!(format!("{}", PipelineStatus::Running), "running");
        assert_eq!(format!("{}", PipelineStatus::Completed), "completed");
        assert_eq!(
            format!("{}", PipelineStatus::Failed("oops".into())),
            "failed: oops"
        );
    }
}
