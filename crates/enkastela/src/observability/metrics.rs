//! Metrics recording trait for enkastela operations.
//!
//! Implement [`MetricsRecorder`] to integrate with your metrics system
//! (Prometheus, StatsD, etc). The default [`NoOpMetrics`] discards all metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Trait for recording operational metrics.
///
/// All methods have default no-op implementations, so you only need to
/// override the metrics you care about.
pub trait MetricsRecorder: Send + Sync {
    fn record_encrypt(&self, _table: &str, _column: &str, _duration: Duration) {}
    fn record_decrypt(&self, _table: &str, _column: &str, _duration: Duration) {}
    fn record_key_cache_hit(&self) {}
    fn record_key_cache_miss(&self) {}
    fn set_key_cache_size(&self, _size: usize) {}
    fn record_audit_event(&self, _action: &str) {}
    fn record_audit_event_dropped(&self) {}
    fn set_audit_queue_size(&self, _size: usize) {}
    fn record_rotation_row(&self, _table: &str) {}
    fn record_error(&self, _error_type: &str) {}
    fn record_blind_index_compute(&self, _table: &str, _column: &str, _duration: Duration) {}
}

/// No-op metrics recorder. Discards all metrics silently.
pub struct NoOpMetrics;
impl MetricsRecorder for NoOpMetrics {}

/// Metrics recorder that tracks counts in-memory (for testing).
pub struct InMemoryMetrics {
    pub encrypts: AtomicU64,
    pub decrypts: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub errors: AtomicU64,
}

impl InMemoryMetrics {
    /// Creates a new `InMemoryMetrics` with all counters at zero.
    pub fn new() -> Self {
        Self {
            encrypts: AtomicU64::new(0),
            decrypts: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

impl Default for InMemoryMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRecorder for InMemoryMetrics {
    fn record_encrypt(&self, _table: &str, _column: &str, _duration: Duration) {
        self.encrypts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_decrypt(&self, _table: &str, _column: &str, _duration: Duration) {
        self.decrypts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_key_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_key_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    fn record_error(&self, _error_type: &str) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_metrics_does_not_panic() {
        let m = NoOpMetrics;
        m.record_encrypt("t", "c", Duration::from_millis(1));
        m.record_decrypt("t", "c", Duration::from_millis(1));
        m.record_key_cache_hit();
        m.record_key_cache_miss();
        m.set_key_cache_size(42);
        m.record_audit_event("insert");
        m.record_audit_event_dropped();
        m.set_audit_queue_size(10);
        m.record_rotation_row("t");
        m.record_error("timeout");
        m.record_blind_index_compute("t", "c", Duration::from_millis(1));
    }

    #[test]
    fn in_memory_counts_encrypts() {
        let m = InMemoryMetrics::new();
        assert_eq!(m.encrypts.load(Ordering::Relaxed), 0);
        m.record_encrypt("users", "email", Duration::from_millis(5));
        m.record_encrypt("users", "ssn", Duration::from_millis(3));
        assert_eq!(m.encrypts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn in_memory_counts_decrypts() {
        let m = InMemoryMetrics::new();
        m.record_decrypt("users", "email", Duration::from_millis(5));
        assert_eq!(m.decrypts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn in_memory_counts_cache_hits_and_misses() {
        let m = InMemoryMetrics::new();
        m.record_key_cache_hit();
        m.record_key_cache_hit();
        m.record_key_cache_miss();
        assert_eq!(m.cache_hits.load(Ordering::Relaxed), 2);
        assert_eq!(m.cache_misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn in_memory_counts_errors() {
        let m = InMemoryMetrics::new();
        m.record_error("timeout");
        m.record_error("crypto");
        m.record_error("io");
        assert_eq!(m.errors.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn in_memory_default_is_zero() {
        let m = InMemoryMetrics::default();
        assert_eq!(m.encrypts.load(Ordering::Relaxed), 0);
        assert_eq!(m.decrypts.load(Ordering::Relaxed), 0);
        assert_eq!(m.cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(m.cache_misses.load(Ordering::Relaxed), 0);
        assert_eq!(m.errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn in_memory_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryMetrics>();
    }

    #[test]
    fn in_memory_concurrent_increments() {
        use std::sync::Arc;

        let m = Arc::new(InMemoryMetrics::new());
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let m = Arc::clone(&m);
                std::thread::spawn(move || {
                    for _ in 0..100 {
                        m.record_encrypt("t", "c", Duration::from_nanos(1));
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(m.encrypts.load(Ordering::Relaxed), 1000);
    }
}
