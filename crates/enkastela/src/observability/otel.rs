//! OpenTelemetry integration for Enkastela.
//!
//! Implements [`MetricsRecorder`] using OpenTelemetry metrics API.
//! Requires the `otel` feature flag.

use std::time::Duration;

use opentelemetry::metrics::{Counter, Histogram, Meter, UpDownCounter};

use super::metrics::MetricsRecorder;

/// OpenTelemetry-backed metrics recorder.
///
/// Uses the OpenTelemetry metrics API for vendor-agnostic telemetry export.
/// Supports any OTel-compatible backend (Prometheus exporter, OTLP, Jaeger, etc).
pub struct OtelMetrics {
    encrypt_total: Counter<u64>,
    decrypt_total: Counter<u64>,
    encrypt_duration: Histogram<f64>,
    decrypt_duration: Histogram<f64>,
    cache_hits: Counter<u64>,
    cache_misses: Counter<u64>,
    _cache_size: UpDownCounter<i64>,
    audit_events: Counter<u64>,
    audit_events_dropped: Counter<u64>,
    _audit_queue_size: UpDownCounter<i64>,
    rotation_rows: Counter<u64>,
    errors: Counter<u64>,
    blind_index_duration: Histogram<f64>,
}

impl OtelMetrics {
    /// Creates a new `OtelMetrics` from an OpenTelemetry `Meter`.
    pub fn new(meter: &Meter) -> Self {
        let encrypt_total = meter
            .u64_counter("enkastela.encrypt.total")
            .with_description("Total number of encrypt operations")
            .build();

        let decrypt_total = meter
            .u64_counter("enkastela.decrypt.total")
            .with_description("Total number of decrypt operations")
            .build();

        let encrypt_duration = meter
            .f64_histogram("enkastela.encrypt.duration")
            .with_description("Duration of encrypt operations in seconds")
            .with_unit("s")
            .build();

        let decrypt_duration = meter
            .f64_histogram("enkastela.decrypt.duration")
            .with_description("Duration of decrypt operations in seconds")
            .with_unit("s")
            .build();

        let cache_hits = meter
            .u64_counter("enkastela.key_cache.hits")
            .with_description("Total key cache hits")
            .build();

        let cache_misses = meter
            .u64_counter("enkastela.key_cache.misses")
            .with_description("Total key cache misses")
            .build();

        let cache_size = meter
            .i64_up_down_counter("enkastela.key_cache.size")
            .with_description("Current key cache size")
            .build();

        let audit_events = meter
            .u64_counter("enkastela.audit.events")
            .with_description("Total audit events recorded")
            .build();

        let audit_events_dropped = meter
            .u64_counter("enkastela.audit.events_dropped")
            .with_description("Total audit events dropped")
            .build();

        let audit_queue_size = meter
            .i64_up_down_counter("enkastela.audit.queue_size")
            .with_description("Current audit queue depth")
            .build();

        let rotation_rows = meter
            .u64_counter("enkastela.rotation.rows")
            .with_description("Total rows re-encrypted")
            .build();

        let errors = meter
            .u64_counter("enkastela.errors")
            .with_description("Total errors by type")
            .build();

        let blind_index_duration = meter
            .f64_histogram("enkastela.blind_index.duration")
            .with_description("Duration of blind index computation in seconds")
            .with_unit("s")
            .build();

        Self {
            encrypt_total,
            decrypt_total,
            encrypt_duration,
            decrypt_duration,
            cache_hits,
            cache_misses,
            _cache_size: cache_size,
            audit_events,
            audit_events_dropped,
            _audit_queue_size: audit_queue_size,
            rotation_rows,
            errors,
            blind_index_duration,
        }
    }
}

impl MetricsRecorder for OtelMetrics {
    fn record_encrypt(&self, table: &str, column: &str, duration: Duration) {
        let attrs = [
            opentelemetry::KeyValue::new("table", table.to_string()),
            opentelemetry::KeyValue::new("column", column.to_string()),
        ];
        self.encrypt_total.add(1, &attrs);
        self.encrypt_duration.record(duration.as_secs_f64(), &attrs);
    }

    fn record_decrypt(&self, table: &str, column: &str, duration: Duration) {
        let attrs = [
            opentelemetry::KeyValue::new("table", table.to_string()),
            opentelemetry::KeyValue::new("column", column.to_string()),
        ];
        self.decrypt_total.add(1, &attrs);
        self.decrypt_duration.record(duration.as_secs_f64(), &attrs);
    }

    fn record_key_cache_hit(&self) {
        self.cache_hits.add(1, &[]);
    }

    fn record_key_cache_miss(&self) {
        self.cache_misses.add(1, &[]);
    }

    fn set_key_cache_size(&self, size: usize) {
        // UpDownCounter doesn't have a set method; we add the delta.
        // For simplicity, we just record the current value as an add.
        // In production, you'd track the previous value and compute the delta.
        // For a gauge-like behavior, use a callback gauge instead.
        let _ = size;
        // No-op for now — OTel UpDownCounter doesn't support direct set.
        // Use OTel observable gauge via meter.u64_observable_gauge() for this.
    }

    fn record_audit_event(&self, action: &str) {
        let attrs = [opentelemetry::KeyValue::new("action", action.to_string())];
        self.audit_events.add(1, &attrs);
    }

    fn record_audit_event_dropped(&self) {
        self.audit_events_dropped.add(1, &[]);
    }

    fn set_audit_queue_size(&self, _size: usize) {
        // Same limitation as set_key_cache_size — use observable gauge.
    }

    fn record_rotation_row(&self, table: &str) {
        let attrs = [opentelemetry::KeyValue::new("table", table.to_string())];
        self.rotation_rows.add(1, &attrs);
    }

    fn record_error(&self, error_type: &str) {
        let attrs = [opentelemetry::KeyValue::new(
            "error_type",
            error_type.to_string(),
        )];
        self.errors.add(1, &attrs);
    }

    fn record_blind_index_compute(&self, table: &str, column: &str, duration: Duration) {
        let attrs = [
            opentelemetry::KeyValue::new("table", table.to_string()),
            opentelemetry::KeyValue::new("column", column.to_string()),
        ];
        self.blind_index_duration
            .record(duration.as_secs_f64(), &attrs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::metrics::MeterProvider;

    fn test_meter() -> Meter {
        let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder().build();
        provider.meter("enkastela-test")
    }

    #[test]
    fn create_and_record() {
        let meter = test_meter();
        let metrics = OtelMetrics::new(&meter);

        // These should not panic
        metrics.record_encrypt("users", "email", Duration::from_millis(5));
        metrics.record_decrypt("users", "ssn", Duration::from_millis(3));
        metrics.record_key_cache_hit();
        metrics.record_key_cache_miss();
        metrics.set_key_cache_size(42);
        metrics.record_audit_event("encrypt");
        metrics.record_audit_event_dropped();
        metrics.set_audit_queue_size(10);
        metrics.record_rotation_row("users");
        metrics.record_error("timeout");
        metrics.record_blind_index_compute("users", "email", Duration::from_micros(100));
    }

    #[test]
    fn is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OtelMetrics>();
    }
}
