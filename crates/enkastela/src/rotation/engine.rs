//! Key rotation engine.

use std::collections::HashMap;
use std::sync::Mutex;

use super::progress::RotationProgress;
use super::strategy::RotationStrategy;
use crate::error::Error;

/// Orchestrates key rotation for encrypted tables.
pub struct RotationEngine {
    active_rotations: Mutex<HashMap<String, RotationProgress>>,
    default_strategy: RotationStrategy,
}

impl RotationEngine {
    /// Creates a new rotation engine with the given default strategy.
    pub fn new(strategy: RotationStrategy) -> Self {
        Self {
            active_rotations: Mutex::new(HashMap::new()),
            default_strategy: strategy,
        }
    }

    /// Starts a new rotation for a table.
    /// Returns error if rotation is already in progress.
    pub fn start_rotation(
        &self,
        table: &str,
        from_version: u32,
        to_version: u32,
    ) -> Result<(), Error> {
        let mut rotations = self.active_rotations.lock().expect("lock poisoned");
        if let Some(existing) = rotations.get(table) {
            if !existing.is_finished() {
                return Err(Error::RotationInProgress(table.to_string()));
            }
        }
        let progress = RotationProgress::new(table, from_version, to_version);
        rotations.insert(table.to_string(), progress);
        Ok(())
    }

    /// Records progress for an active rotation.
    pub fn record_progress(
        &self,
        table: &str,
        rows_processed: u64,
        last_id: Option<String>,
    ) -> Result<(), Error> {
        let mut rotations = self.active_rotations.lock().expect("lock poisoned");
        let progress = rotations.get_mut(table).ok_or_else(|| Error::KeyNotFound {
            purpose: "rotation".to_string(),
            scope: table.to_string(),
        })?;

        if progress.is_finished() {
            return Err(Error::KeyNotFound {
                purpose: "rotation".to_string(),
                scope: table.to_string(),
            });
        }

        progress.advance(rows_processed, last_id);
        Ok(())
    }

    /// Marks a rotation as complete.
    pub fn complete_rotation(&self, table: &str) -> Result<(), Error> {
        let mut rotations = self.active_rotations.lock().expect("lock poisoned");
        let progress = rotations.get_mut(table).ok_or_else(|| Error::KeyNotFound {
            purpose: "rotation".to_string(),
            scope: table.to_string(),
        })?;
        progress.complete();
        Ok(())
    }

    /// Gets current progress for a table rotation.
    pub fn get_progress(&self, table: &str) -> Option<RotationProgress> {
        let rotations = self.active_rotations.lock().expect("lock poisoned");
        rotations.get(table).cloned()
    }

    /// Checks if a table has an active rotation.
    pub fn is_rotating(&self, table: &str) -> bool {
        let rotations = self.active_rotations.lock().expect("lock poisoned");
        rotations
            .get(table)
            .map(|p| !p.is_finished())
            .unwrap_or(false)
    }

    /// Returns the default strategy.
    pub fn strategy(&self) -> RotationStrategy {
        self.default_strategy
    }

    /// Lists all active (non-finished) rotations.
    pub fn active_rotations(&self) -> Vec<RotationProgress> {
        let rotations = self.active_rotations.lock().expect("lock poisoned");
        rotations
            .values()
            .filter(|p| !p.is_finished())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::progress::RotationStatus;
    use super::*;

    #[test]
    fn start_and_complete_rotation() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        engine.start_rotation("users", 1, 2).unwrap();

        assert!(engine.is_rotating("users"));

        engine.complete_rotation("users").unwrap();

        assert!(!engine.is_rotating("users"));

        let progress = engine.get_progress("users").unwrap();
        assert_eq!(progress.status, RotationStatus::Completed);
        assert!(progress.completed_at.is_some());
    }

    #[test]
    fn start_rotation_when_already_in_progress_fails() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        engine.start_rotation("users", 1, 2).unwrap();

        let err = engine.start_rotation("users", 1, 2).unwrap_err();
        assert!(matches!(err, Error::RotationInProgress(ref t) if t == "users"));
    }

    #[test]
    fn start_rotation_after_completed_succeeds() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        engine.start_rotation("users", 1, 2).unwrap();
        engine.complete_rotation("users").unwrap();

        // Should be able to start a new rotation after completion
        engine.start_rotation("users", 2, 3).unwrap();
        assert!(engine.is_rotating("users"));
    }

    #[test]
    fn record_progress_updates_correctly() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        engine.start_rotation("users", 1, 2).unwrap();

        engine
            .record_progress("users", 100, Some("id-100".to_string()))
            .unwrap();

        let progress = engine.get_progress("users").unwrap();
        assert_eq!(progress.processed_rows, 100);
        assert_eq!(progress.last_processed_id.as_deref(), Some("id-100"));

        engine
            .record_progress("users", 50, Some("id-150".to_string()))
            .unwrap();

        let progress = engine.get_progress("users").unwrap();
        assert_eq!(progress.processed_rows, 150);
        assert_eq!(progress.last_processed_id.as_deref(), Some("id-150"));
    }

    #[test]
    fn get_progress_returns_current_state() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        assert!(engine.get_progress("users").is_none());

        engine.start_rotation("users", 1, 2).unwrap();
        let progress = engine.get_progress("users").unwrap();
        assert_eq!(progress.from_version, 1);
        assert_eq!(progress.to_version, 2);
        assert_eq!(progress.status, RotationStatus::InProgress);
    }

    #[test]
    fn multiple_table_rotations_independent() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        engine.start_rotation("users", 1, 2).unwrap();
        engine.start_rotation("orders", 3, 4).unwrap();

        assert!(engine.is_rotating("users"));
        assert!(engine.is_rotating("orders"));

        engine.complete_rotation("users").unwrap();

        assert!(!engine.is_rotating("users"));
        assert!(engine.is_rotating("orders"));
    }

    #[test]
    fn complete_clears_active_rotation() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        engine.start_rotation("users", 1, 2).unwrap();
        engine.start_rotation("orders", 3, 4).unwrap();

        engine.complete_rotation("users").unwrap();

        let active = engine.active_rotations();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].table, "orders");
    }

    #[test]
    fn strategy_returns_configured_value() {
        let engine = RotationEngine::new(RotationStrategy::Eager { batch_size: 500 });
        assert_eq!(
            engine.strategy(),
            RotationStrategy::Eager { batch_size: 500 }
        );
    }

    #[test]
    fn is_rotating_false_for_unknown_table() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        assert!(!engine.is_rotating("nonexistent"));
    }

    #[test]
    fn record_progress_on_nonexistent_table_fails() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        let err = engine.record_progress("nonexistent", 10, None).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }));
    }

    #[test]
    fn record_progress_on_completed_rotation_fails() {
        let engine = RotationEngine::new(RotationStrategy::Lazy);
        engine.start_rotation("users", 1, 2).unwrap();
        engine.complete_rotation("users").unwrap();

        let err = engine.record_progress("users", 10, None).unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }));
    }
}
