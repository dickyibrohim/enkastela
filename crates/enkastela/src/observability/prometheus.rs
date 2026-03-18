//! Prometheus metrics recorder for Enkastela.
//!
//! Implements [`MetricsRecorder`] using Prometheus counters, histograms,
//! and gauges. Requires the `metrics-prometheus` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use enkastela::observability::prometheus::PrometheusMetrics;
//!
//! let metrics = PrometheusMetrics::new();
//! // Register with your Prometheus registry
//! // Then pass to Vault builder
//! ```

use std::time::Duration;

use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry};

use super::metrics::MetricsRecorder;

/// Prometheus-backed metrics recorder.
///
/// All metrics are prefixed with `enkastela_` and labeled by table/column
/// where applicable.
pub struct PrometheusMetrics {
    /// Duration of encrypt operations in seconds.
    encrypt_duration: HistogramVec,
    /// Duration of decrypt operations in seconds.
    decrypt_duration: HistogramVec,
    /// Total encrypt operations.
    encrypt_total: IntCounterVec,
    /// Total decrypt operations.
    decrypt_total: IntCounterVec,
    /// Key cache hits.
    cache_hits: IntCounterVec,
    /// Key cache misses.
    cache_misses: IntCounterVec,
    /// Current key cache size.
    cache_size: IntGaugeVec,
    /// Total audit events recorded.
    audit_events: IntCounterVec,
    /// Total audit events dropped.
    audit_events_dropped: IntCounterVec,
    /// Current audit queue size.
    audit_queue_size: IntGaugeVec,
    /// Total rows re-encrypted during rotation.
    rotation_rows: IntCounterVec,
    /// Total errors by type.
    errors: IntCounterVec,
    /// Duration of blind index computation in seconds.
    blind_index_duration: HistogramVec,
}

impl PrometheusMetrics {
    /// Creates a new `PrometheusMetrics` registered with the default global registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Self::with_registry(prometheus::default_registry())
    }

    /// Creates a new `PrometheusMetrics` registered with a custom registry.
    pub fn with_registry(registry: &Registry) -> Result<Self, prometheus::Error> {
        let duration_buckets = vec![
            0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
        ];

        let encrypt_duration = HistogramVec::new(
            HistogramOpts::new(
                "enkastela_encrypt_duration_seconds",
                "Duration of encrypt operations in seconds",
            )
            .buckets(duration_buckets.clone()),
            &["table", "column"],
        )?;

        let decrypt_duration = HistogramVec::new(
            HistogramOpts::new(
                "enkastela_decrypt_duration_seconds",
                "Duration of decrypt operations in seconds",
            )
            .buckets(duration_buckets.clone()),
            &["table", "column"],
        )?;

        let encrypt_total = IntCounterVec::new(
            Opts::new(
                "enkastela_encrypt_total",
                "Total number of encrypt operations",
            ),
            &["table", "column"],
        )?;

        let decrypt_total = IntCounterVec::new(
            Opts::new(
                "enkastela_decrypt_total",
                "Total number of decrypt operations",
            ),
            &["table", "column"],
        )?;

        let cache_hits = IntCounterVec::new(
            Opts::new("enkastela_key_cache_hits_total", "Total key cache hits"),
            &[],
        )?;

        let cache_misses = IntCounterVec::new(
            Opts::new("enkastela_key_cache_misses_total", "Total key cache misses"),
            &[],
        )?;

        let cache_size = IntGaugeVec::new(
            Opts::new(
                "enkastela_key_cache_size",
                "Current number of keys in the cache",
            ),
            &[],
        )?;

        let audit_events = IntCounterVec::new(
            Opts::new(
                "enkastela_audit_events_total",
                "Total audit events recorded",
            ),
            &["action"],
        )?;

        let audit_events_dropped = IntCounterVec::new(
            Opts::new(
                "enkastela_audit_events_dropped_total",
                "Total audit events dropped due to queue overflow",
            ),
            &[],
        )?;

        let audit_queue_size = IntGaugeVec::new(
            Opts::new(
                "enkastela_audit_queue_size",
                "Current audit event queue depth",
            ),
            &[],
        )?;

        let rotation_rows = IntCounterVec::new(
            Opts::new(
                "enkastela_rotation_rows_total",
                "Total rows re-encrypted during key rotation",
            ),
            &["table"],
        )?;

        let errors = IntCounterVec::new(
            Opts::new("enkastela_errors_total", "Total errors by type"),
            &["error_type"],
        )?;

        let blind_index_duration = HistogramVec::new(
            HistogramOpts::new(
                "enkastela_blind_index_duration_seconds",
                "Duration of blind index computation in seconds",
            )
            .buckets(duration_buckets),
            &["table", "column"],
        )?;

        registry.register(Box::new(encrypt_duration.clone()))?;
        registry.register(Box::new(decrypt_duration.clone()))?;
        registry.register(Box::new(encrypt_total.clone()))?;
        registry.register(Box::new(decrypt_total.clone()))?;
        registry.register(Box::new(cache_hits.clone()))?;
        registry.register(Box::new(cache_misses.clone()))?;
        registry.register(Box::new(cache_size.clone()))?;
        registry.register(Box::new(audit_events.clone()))?;
        registry.register(Box::new(audit_events_dropped.clone()))?;
        registry.register(Box::new(audit_queue_size.clone()))?;
        registry.register(Box::new(rotation_rows.clone()))?;
        registry.register(Box::new(errors.clone()))?;
        registry.register(Box::new(blind_index_duration.clone()))?;

        Ok(Self {
            encrypt_duration,
            decrypt_duration,
            encrypt_total,
            decrypt_total,
            cache_hits,
            cache_misses,
            cache_size,
            audit_events,
            audit_events_dropped,
            audit_queue_size,
            rotation_rows,
            errors,
            blind_index_duration,
        })
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new().expect("failed to register Prometheus metrics")
    }
}

impl MetricsRecorder for PrometheusMetrics {
    fn record_encrypt(&self, table: &str, column: &str, duration: Duration) {
        self.encrypt_total.with_label_values(&[table, column]).inc();
        self.encrypt_duration
            .with_label_values(&[table, column])
            .observe(duration.as_secs_f64());
    }

    fn record_decrypt(&self, table: &str, column: &str, duration: Duration) {
        self.decrypt_total.with_label_values(&[table, column]).inc();
        self.decrypt_duration
            .with_label_values(&[table, column])
            .observe(duration.as_secs_f64());
    }

    fn record_key_cache_hit(&self) {
        self.cache_hits.with_label_values(&[] as &[&str]).inc();
    }

    fn record_key_cache_miss(&self) {
        self.cache_misses.with_label_values(&[] as &[&str]).inc();
    }

    fn set_key_cache_size(&self, size: usize) {
        self.cache_size
            .with_label_values(&[] as &[&str])
            .set(size as i64);
    }

    fn record_audit_event(&self, action: &str) {
        self.audit_events.with_label_values(&[action]).inc();
    }

    fn record_audit_event_dropped(&self) {
        self.audit_events_dropped
            .with_label_values(&[] as &[&str])
            .inc();
    }

    fn set_audit_queue_size(&self, size: usize) {
        self.audit_queue_size
            .with_label_values(&[] as &[&str])
            .set(size as i64);
    }

    fn record_rotation_row(&self, table: &str) {
        self.rotation_rows.with_label_values(&[table]).inc();
    }

    fn record_error(&self, error_type: &str) {
        self.errors.with_label_values(&[error_type]).inc();
    }

    fn record_blind_index_compute(&self, table: &str, column: &str, duration: Duration) {
        self.blind_index_duration
            .with_label_values(&[table, column])
            .observe(duration.as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_registry() -> Registry {
        Registry::new()
    }

    #[test]
    fn create_with_custom_registry() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();
        metrics.record_encrypt("users", "email", Duration::from_millis(5));
        assert_eq!(
            metrics
                .encrypt_total
                .with_label_values(&["users", "email"])
                .get(),
            1
        );
    }

    #[test]
    fn encrypt_records_counter_and_histogram() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();

        metrics.record_encrypt("users", "email", Duration::from_millis(10));
        metrics.record_encrypt("users", "email", Duration::from_millis(20));
        metrics.record_encrypt("orders", "address", Duration::from_millis(5));

        assert_eq!(
            metrics
                .encrypt_total
                .with_label_values(&["users", "email"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .encrypt_total
                .with_label_values(&["orders", "address"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .encrypt_duration
                .with_label_values(&["users", "email"])
                .get_sample_count(),
            2
        );
    }

    #[test]
    fn decrypt_records_counter_and_histogram() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();

        metrics.record_decrypt("users", "ssn", Duration::from_millis(7));
        assert_eq!(
            metrics
                .decrypt_total
                .with_label_values(&["users", "ssn"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .decrypt_duration
                .with_label_values(&["users", "ssn"])
                .get_sample_count(),
            1
        );
    }

    #[test]
    fn cache_hit_miss_counters() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();

        metrics.record_key_cache_hit();
        metrics.record_key_cache_hit();
        metrics.record_key_cache_miss();

        assert_eq!(
            metrics.cache_hits.with_label_values(&[] as &[&str]).get(),
            2
        );
        assert_eq!(
            metrics.cache_misses.with_label_values(&[] as &[&str]).get(),
            1
        );
    }

    #[test]
    fn cache_size_gauge() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();

        metrics.set_key_cache_size(42);
        assert_eq!(
            metrics.cache_size.with_label_values(&[] as &[&str]).get(),
            42
        );

        metrics.set_key_cache_size(10);
        assert_eq!(
            metrics.cache_size.with_label_values(&[] as &[&str]).get(),
            10
        );
    }

    #[test]
    fn audit_event_counters() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();

        metrics.record_audit_event("encrypt");
        metrics.record_audit_event("encrypt");
        metrics.record_audit_event("decrypt");
        metrics.record_audit_event_dropped();

        assert_eq!(
            metrics.audit_events.with_label_values(&["encrypt"]).get(),
            2
        );
        assert_eq!(
            metrics.audit_events.with_label_values(&["decrypt"]).get(),
            1
        );
        assert_eq!(
            metrics
                .audit_events_dropped
                .with_label_values(&[] as &[&str])
                .get(),
            1
        );
    }

    #[test]
    fn rotation_and_error_counters() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();

        metrics.record_rotation_row("users");
        metrics.record_rotation_row("users");
        metrics.record_rotation_row("orders");
        metrics.record_error("timeout");
        metrics.record_error("crypto");

        assert_eq!(metrics.rotation_rows.with_label_values(&["users"]).get(), 2);
        assert_eq!(
            metrics.rotation_rows.with_label_values(&["orders"]).get(),
            1
        );
        assert_eq!(metrics.errors.with_label_values(&["timeout"]).get(), 1);
        assert_eq!(metrics.errors.with_label_values(&["crypto"]).get(), 1);
    }

    #[test]
    fn blind_index_histogram() {
        let registry = fresh_registry();
        let metrics = PrometheusMetrics::with_registry(&registry).unwrap();

        metrics.record_blind_index_compute("users", "email", Duration::from_micros(500));
        assert_eq!(
            metrics
                .blind_index_duration
                .with_label_values(&["users", "email"])
                .get_sample_count(),
            1
        );
    }

    #[test]
    fn is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PrometheusMetrics>();
    }
}
