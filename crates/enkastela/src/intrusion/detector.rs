//! Intrusion detection — monitors decrypt operations for poison record access.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::poison::PoisonRegistry;

/// Severity level of an intrusion alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertSeverity {
    /// Low — may be a false positive or authorized test.
    Low,
    /// Medium — suspicious activity.
    Medium,
    /// High — likely unauthorized access.
    High,
    /// Critical — confirmed breach indicator.
    Critical,
}

/// An intrusion alert fired when a poison record is accessed.
#[derive(Debug, Clone)]
pub struct IntrusionAlert {
    /// Table containing the accessed poison record.
    pub table: String,
    /// Column accessed.
    pub column: String,
    /// Row identifier of the poison record.
    pub row_id: String,
    /// Severity assessment.
    pub severity: AlertSeverity,
    /// Timestamp of the access.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Additional context.
    pub context: Option<String>,
}

/// Trait for handling intrusion alerts.
pub trait AlertHandler: Send + Sync {
    /// Called when a poison record is accessed.
    fn handle_alert(&self, alert: &IntrusionAlert);
}

/// A simple alert handler that logs to tracing.
pub struct LogAlertHandler;

impl AlertHandler for LogAlertHandler {
    fn handle_alert(&self, alert: &IntrusionAlert) {
        tracing::error!(
            table = %alert.table,
            column = %alert.column,
            row_id = %alert.row_id,
            severity = ?alert.severity,
            "INTRUSION DETECTED: poison record accessed"
        );
    }
}

/// Monitors decrypt operations and fires alerts on poison record access.
pub struct IntrusionDetector {
    registry: Arc<PoisonRegistry>,
    handlers: Vec<Box<dyn AlertHandler>>,
    alert_count: AtomicU64,
}

impl IntrusionDetector {
    /// Creates a new detector with the given poison registry.
    pub fn new(registry: Arc<PoisonRegistry>) -> Self {
        Self {
            registry,
            handlers: Vec::new(),
            alert_count: AtomicU64::new(0),
        }
    }

    /// Adds an alert handler.
    pub fn add_handler(&mut self, handler: impl AlertHandler + 'static) {
        self.handlers.push(Box::new(handler));
    }

    /// Checks if a decrypt operation targets a poison record.
    ///
    /// If it does, fires alerts through all registered handlers and returns `true`.
    pub fn check_access(&self, table: &str, column: &str, row_id: &str) -> bool {
        if self.registry.is_poison(table, column, row_id) {
            let alert = IntrusionAlert {
                table: table.to_string(),
                column: column.to_string(),
                row_id: row_id.to_string(),
                severity: AlertSeverity::Critical,
                timestamp: chrono::Utc::now(),
                context: None,
            };

            for handler in &self.handlers {
                handler.handle_alert(&alert);
            }

            self.alert_count.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Returns the total number of alerts fired.
    pub fn alert_count(&self) -> u64 {
        self.alert_count.load(Ordering::Relaxed)
    }

    /// Returns a reference to the poison registry.
    pub fn registry(&self) -> &PoisonRegistry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64 as StdAtomicU64;

    struct CountingHandler {
        count: Arc<StdAtomicU64>,
    }

    impl AlertHandler for CountingHandler {
        fn handle_alert(&self, _alert: &IntrusionAlert) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn detect_poison_access() {
        let registry = Arc::new(PoisonRegistry::new());
        registry.register(super::super::poison::PoisonRecord::new(
            "users",
            "email",
            "canary-1",
            b"trap@test.internal",
        ));

        let handler_count = Arc::new(StdAtomicU64::new(0));
        let mut detector = IntrusionDetector::new(registry);
        detector.add_handler(CountingHandler {
            count: handler_count.clone(),
        });

        // Normal access — no alert
        assert!(!detector.check_access("users", "email", "real-user-123"));
        assert_eq!(handler_count.load(Ordering::Relaxed), 0);

        // Poison access — alert!
        assert!(detector.check_access("users", "email", "canary-1"));
        assert_eq!(handler_count.load(Ordering::Relaxed), 1);
        assert_eq!(detector.alert_count(), 1);
    }

    #[test]
    fn multiple_handlers() {
        let registry = Arc::new(PoisonRegistry::new());
        registry.register(super::super::poison::PoisonRecord::new(
            "t", "c", "poison", b"x",
        ));

        let c1 = Arc::new(StdAtomicU64::new(0));
        let c2 = Arc::new(StdAtomicU64::new(0));
        let mut detector = IntrusionDetector::new(registry);
        detector.add_handler(CountingHandler { count: c1.clone() });
        detector.add_handler(CountingHandler { count: c2.clone() });

        detector.check_access("t", "c", "poison");
        assert_eq!(c1.load(Ordering::Relaxed), 1);
        assert_eq!(c2.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn no_false_positives() {
        let registry = Arc::new(PoisonRegistry::new());
        let detector = IntrusionDetector::new(registry);

        assert!(!detector.check_access("users", "email", "user-1"));
        assert!(!detector.check_access("users", "email", "user-2"));
        assert_eq!(detector.alert_count(), 0);
    }
}
