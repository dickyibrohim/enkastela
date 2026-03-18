//! Async batched audit logger.
//!
//! [`AuditLogger`] accepts audit events through a bounded mpsc channel and
//! flushes them in batches to a pluggable [`AuditSink`]. Batching reduces
//! write amplification while the bounded channel provides back-pressure.
//!
//! The background flush task fires when either:
//! - `batch_size` events have accumulated, or
//! - `flush_interval` has elapsed since the last flush.
//!
//! On shutdown, remaining buffered events are drained and flushed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Notify};
use tokio::time::Duration;

use super::events::{AuditEvent, AuditEventBuilder, EventHasher};
use crate::error::Error;

/// Policy for handling a full event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Block the caller until space is available or the timeout elapses.
    /// If the timeout elapses, returns [`Error::AuditQueueFull`].
    BlockWithTimeout(Duration),
    /// Drop the event silently and increment the drop counter.
    DropAndCount,
}

/// Trait for audit log storage backends.
///
/// Implementations receive batches of events and persist them durably.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    /// Write a batch of events to the storage backend.
    ///
    /// Implementations should persist the entire batch atomically when possible.
    async fn write_batch(&self, events: Vec<AuditEvent>) -> Result<(), Error>;
}

/// In-memory audit sink for testing.
///
/// Stores all received events in a `Mutex<Vec<AuditEvent>>` for later inspection.
pub struct InMemoryAuditSink {
    events: std::sync::Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditSink {
    /// Create a new empty in-memory sink.
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Return a snapshot of all stored events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Return the number of stored events.
    pub fn len(&self) -> usize {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Return `true` if no events have been stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuditSink for InMemoryAuditSink {
    async fn write_batch(&self, events: Vec<AuditEvent>) -> Result<(), Error> {
        let mut store = self
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.extend(events);
        Ok(())
    }
}

/// Async batched audit logger.
///
/// Buffers events in a bounded mpsc channel and flushes them to an [`AuditSink`]
/// either when `batch_size` is reached or `flush_interval` elapses.
///
/// The logger maintains the HMAC hash chain across batches by tracking the
/// previous event's hash in the background task.
pub struct AuditLogger {
    tx: mpsc::Sender<AuditEvent>,
    overflow_policy: OverflowPolicy,
    dropped_count: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    /// Handle to the background flush task so we can await it on shutdown.
    flush_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AuditLogger {
    /// Create a new logger and spawn the background flush task.
    ///
    /// # Arguments
    ///
    /// - `sink` -- storage backend to flush events to
    /// - `hasher` -- event hasher for HMAC chain computation
    /// - `batch_size` -- maximum events per flush (default 100)
    /// - `flush_interval` -- maximum time between flushes (default 1 second)
    /// - `queue_capacity` -- bounded channel capacity (default 10,000)
    /// - `overflow_policy` -- what to do when the queue is full
    pub fn new(
        sink: Arc<dyn AuditSink>,
        hasher: Arc<dyn EventHasher>,
        batch_size: usize,
        flush_interval: Duration,
        queue_capacity: usize,
        overflow_policy: OverflowPolicy,
    ) -> Self {
        let (tx, rx) = mpsc::channel(queue_capacity);
        let dropped_count = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let shutdown_notify = Arc::new(Notify::new());

        let handle = tokio::spawn(flush_task(
            rx,
            sink,
            hasher,
            batch_size,
            flush_interval,
            Arc::clone(&running),
            Arc::clone(&shutdown_notify),
        ));

        Self {
            tx,
            overflow_policy,
            dropped_count,
            running,
            shutdown_notify,
            flush_handle: tokio::sync::Mutex::new(Some(handle)),
        }
    }

    /// Log an audit event.
    ///
    /// The event is built from the provided builder with a placeholder hash.
    /// The background flush task recomputes the real HMAC hash to maintain
    /// chain continuity.
    ///
    /// Depending on the [`OverflowPolicy`], this method may block briefly
    /// or drop the event when the queue is full.
    pub async fn log(&self, builder: AuditEventBuilder) -> Result<(), Error> {
        // Build a preliminary event with a placeholder hash. The flush task
        // recomputes the real hash with the correct prev_hash for chain
        // continuity.
        let preliminary_event = builder.build(&NoOpHasher, None);

        match self.overflow_policy {
            OverflowPolicy::BlockWithTimeout(timeout) => {
                match tokio::time::timeout(timeout, self.tx.send(preliminary_event)).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => {
                        // Channel closed (logger shut down)
                        Err(Error::AuditQueueFull)
                    }
                    Err(_elapsed) => Err(Error::AuditQueueFull),
                }
            }
            OverflowPolicy::DropAndCount => match self.tx.try_send(preliminary_event) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::AuditQueueFull),
            },
        }
    }

    /// Returns the number of events dropped due to queue overflow.
    ///
    /// Only incremented when [`OverflowPolicy::DropAndCount`] is in effect.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Gracefully shut down the logger, flushing all remaining events.
    ///
    /// After this method returns, no further events will be accepted.
    pub async fn shutdown(&self) {
        // Signal the flush task to stop and wake it immediately
        self.running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_one();

        // Wait for the flush task to complete
        let mut handle_guard = self.flush_handle.lock().await;
        if let Some(handle) = handle_guard.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for AuditLogger {
    fn drop(&mut self) {
        // Signal the flush task to drain remaining events.
        // The background task will flush when it receives the shutdown notification
        // and the channel sender is dropped.
        self.running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_one();
    }
}

/// No-op hasher used for preliminary event construction before the flush task
/// applies the real HMAC chain.
struct NoOpHasher;

impl super::events::EventHasher for NoOpHasher {
    fn hash_event(&self, _event_data: &[u8], _prev_hash: Option<&[u8]>) -> Vec<u8> {
        vec![0u8; 32]
    }
}

/// Recompute the HMAC hash for an event and update its chain fields.
fn rehash_event(event: &mut AuditEvent, hasher: &dyn EventHasher, prev_hash: &mut Option<Vec<u8>>) {
    let event_data = super::events::serialize_event_data(
        event.id,
        &event.timestamp,
        &event.action,
        event.table_name.as_deref(),
        event.column_name.as_deref(),
        event.row_id.as_deref(),
        event.actor.as_deref(),
        event.key_version,
        event.metadata.as_ref(),
    );
    let real_hash = hasher.hash_event(&event_data, prev_hash.as_deref());
    event.prev_hash = prev_hash.clone();
    event.event_hash = real_hash.clone();
    *prev_hash = Some(real_hash);
}

/// Background task that receives events and flushes them in batches.
async fn flush_task(
    mut rx: mpsc::Receiver<AuditEvent>,
    sink: Arc<dyn AuditSink>,
    hasher: Arc<dyn EventHasher>,
    batch_size: usize,
    flush_interval: Duration,
    _running: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
) {
    let mut batch: Vec<AuditEvent> = Vec::with_capacity(batch_size);
    let mut prev_hash: Option<Vec<u8>> = None;
    let mut interval = tokio::time::interval(flush_interval);
    // The first tick completes immediately; consume it.
    interval.tick().await;

    loop {
        tokio::select! {
            biased;

            // Highest priority: receive events from the channel
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(mut event) => {
                        rehash_event(&mut event, hasher.as_ref(), &mut prev_hash);
                        batch.push(event);

                        if batch.len() >= batch_size {
                            flush_batch(&sink, &mut batch).await;
                        }
                    }
                    None => {
                        // Channel closed, flush remaining and exit
                        if !batch.is_empty() {
                            flush_batch(&sink, &mut batch).await;
                        }
                        return;
                    }
                }
            }

            // Timer-based flush
            _ = interval.tick() => {
                if !batch.is_empty() {
                    flush_batch(&sink, &mut batch).await;
                }
            }

            // Shutdown signal: drain remaining and exit
            _ = shutdown_notify.notified() => {
                // Drain any remaining events from the channel
                while let Ok(mut event) = rx.try_recv() {
                    rehash_event(&mut event, hasher.as_ref(), &mut prev_hash);
                    batch.push(event);
                }
                if !batch.is_empty() {
                    flush_batch(&sink, &mut batch).await;
                }
                return;
            }
        }
    }
}

/// Flush the accumulated batch to the sink.
async fn flush_batch(sink: &Arc<dyn AuditSink>, batch: &mut Vec<AuditEvent>) {
    let events: Vec<AuditEvent> = std::mem::take(batch);
    if let Err(e) = sink.write_batch(events).await {
        // Log the error but do not panic -- audit failures should not crash
        // the application.
        tracing::error!("audit sink write_batch failed: {}", e);
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL audit sink
// ---------------------------------------------------------------------------

/// PostgreSQL-backed audit sink.
///
/// Persists audit event batches to the `enkastela.audit_log` table.
pub struct PostgresAuditSink {
    pool: sqlx::PgPool,
}

impl PostgresAuditSink {
    /// Creates a new sink backed by the given connection pool.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AuditSink for PostgresAuditSink {
    async fn write_batch(&self, events: Vec<AuditEvent>) -> Result<(), Error> {
        for event in &events {
            let action_str = serde_json::to_value(event.action)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", event.action));

            let to_hex =
                |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };

            let details = serde_json::json!({
                "row_id": event.row_id,
                "key_version": event.key_version,
                "prev_hash": event.prev_hash.as_ref().map(|h| to_hex(h)),
                "event_hash": to_hex(&event.event_hash),
                "metadata": event.metadata,
            });

            sqlx::query(
                r#"INSERT INTO enkastela.audit_log
                    (event_type, table_name, column_name, performed_by, details)
                VALUES ($1, $2, $3, $4, $5)"#,
            )
            .bind(&action_str)
            .bind(event.table_name.as_deref())
            .bind(event.column_name.as_deref())
            .bind(event.actor.as_deref())
            .bind(&details)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(Box::new(e)))?;
        }
        Ok(())
    }
}

/// Counts the number of audit events stored in the `enkastela.audit_log` table.
pub async fn count_audit_events(pool: &sqlx::PgPool) -> Result<i64, Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM enkastela.audit_log")
        .fetch_one(pool)
        .await
        .map_err(|e| Error::Database(Box::new(e)))?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::{AuditAction, AuditEventBuilder};
    use crate::audit::integrity::{verify_chain, HmacEventHasher};
    use crate::crypto::secret::SecretKey;

    fn test_key() -> SecretKey {
        SecretKey::from_bytes([0x42; 32])
    }

    fn make_hasher() -> Arc<dyn EventHasher> {
        Arc::new(HmacEventHasher::new(SecretKey::from_bytes([0x42; 32])))
    }

    fn make_sink() -> Arc<InMemoryAuditSink> {
        Arc::new(InMemoryAuditSink::new())
    }

    #[tokio::test]
    async fn log_single_event() {
        let sink = make_sink();
        let logger = AuditLogger::new(
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            make_hasher(),
            100,
            Duration::from_millis(50),
            1000,
            OverflowPolicy::DropAndCount,
        );

        logger
            .log(
                AuditEventBuilder::new(AuditAction::Encrypt)
                    .table("users")
                    .column("email")
                    .row_id("1")
                    .actor("test"),
            )
            .await
            .unwrap();

        // Wait for flush interval to trigger
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(sink.len(), 1);
        let events = sink.events();
        assert_eq!(events[0].action, AuditAction::Encrypt);
        assert_eq!(events[0].table_name.as_deref(), Some("users"));
        assert_eq!(events[0].column_name.as_deref(), Some("email"));
        assert_eq!(events[0].row_id.as_deref(), Some("1"));
        assert_eq!(events[0].actor.as_deref(), Some("test"));

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn batch_flush_works() {
        let sink = make_sink();
        let batch_size = 5;
        let logger = AuditLogger::new(
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            make_hasher(),
            batch_size,
            Duration::from_secs(300), // long interval so only batch_size triggers flush
            1000,
            OverflowPolicy::DropAndCount,
        );

        // Send exactly batch_size events
        for i in 0..batch_size {
            logger
                .log(
                    AuditEventBuilder::new(AuditAction::Encrypt)
                        .table("t")
                        .row_id(format!("{}", i)),
                )
                .await
                .unwrap();
        }

        // Give the background task time to process the batch
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(sink.len(), batch_size);

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn drop_policy_counts_drops() {
        let sink = make_sink();
        // Use a slow sink to guarantee the queue fills up
        let slow_sink: Arc<dyn AuditSink> = Arc::new(SlowSink {
            inner: Arc::clone(&sink),
        });

        let logger = AuditLogger::new(
            slow_sink,
            make_hasher(),
            1000,                     // large batch size so nothing flushes via batch trigger
            Duration::from_secs(300), // long interval
            2,                        // very small queue
            OverflowPolicy::DropAndCount,
        );

        // Flood the queue -- with capacity=2 and no flushing, most should be dropped
        for _ in 0..100 {
            let _ = logger
                .log(AuditEventBuilder::new(AuditAction::Encrypt).table("t"))
                .await;
        }

        let dropped = logger.dropped_count();
        assert!(
            dropped > 0,
            "expected some drops with capacity=2 and 100 events, got dropped={}",
            dropped
        );

        logger.shutdown().await;
    }

    /// A sink wrapper that doesn't actually slow anything but helps with testing.
    struct SlowSink {
        inner: Arc<InMemoryAuditSink>,
    }

    #[async_trait::async_trait]
    impl AuditSink for SlowSink {
        async fn write_batch(&self, events: Vec<AuditEvent>) -> Result<(), Error> {
            self.inner.write_batch(events).await
        }
    }

    #[tokio::test]
    async fn shutdown_flushes_remaining() {
        let sink = make_sink();
        let logger = AuditLogger::new(
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            make_hasher(),
            1000,                     // large batch, so timer flush is the only mechanism
            Duration::from_secs(300), // long interval
            10000,
            OverflowPolicy::DropAndCount,
        );

        // Log a few events
        for i in 0..3 {
            logger
                .log(
                    AuditEventBuilder::new(AuditAction::Decrypt)
                        .table("orders")
                        .row_id(format!("{}", i)),
                )
                .await
                .unwrap();
        }

        // Small yield to ensure events are in the channel
        tokio::task::yield_now().await;

        // Shutdown should flush remaining events immediately via notify
        logger.shutdown().await;

        assert_eq!(sink.len(), 3);
    }

    #[tokio::test]
    async fn events_have_correct_hash_chain() {
        let sink = make_sink();
        let key = test_key();
        let logger = AuditLogger::new(
            Arc::clone(&sink) as Arc<dyn AuditSink>,
            make_hasher(),
            100,
            Duration::from_millis(50),
            1000,
            OverflowPolicy::DropAndCount,
        );

        for i in 0..5 {
            logger
                .log(
                    AuditEventBuilder::new(AuditAction::Encrypt)
                        .table("users")
                        .column("email")
                        .row_id(format!("{}", i))
                        .actor("chain-test")
                        .key_version(1),
                )
                .await
                .unwrap();
        }

        // Wait for flush
        tokio::time::sleep(Duration::from_millis(150)).await;
        logger.shutdown().await;

        let events = sink.events();
        assert_eq!(events.len(), 5);

        // Verify the hash chain
        assert!(
            verify_chain(&key, &events).unwrap(),
            "hash chain verification failed"
        );

        // First event should have no prev_hash
        assert!(events[0].prev_hash.is_none());

        // Subsequent events should chain to the previous
        for i in 1..events.len() {
            assert_eq!(
                events[i].prev_hash.as_deref(),
                Some(events[i - 1].event_hash.as_slice()),
                "prev_hash mismatch at index {}",
                i
            );
        }
    }

    #[tokio::test]
    async fn block_with_timeout_returns_error_on_full_queue() {
        // Use a channel of capacity 1 with a sender we hold onto, to simulate
        // a full channel without relying on timing. We construct the logger
        // manually so the background task is stalled by a PausingSink.
        let pause = Arc::new(Notify::new());
        let pausing_sink: Arc<dyn AuditSink> = Arc::new(PausingSink {
            pause: Arc::clone(&pause),
            inner: Arc::new(InMemoryAuditSink::new()),
            paused_once: std::sync::atomic::AtomicBool::new(false),
        });

        // batch_size = 1 so the flush task tries to flush after every event,
        // then blocks on the PausingSink, which prevents it from draining the
        // channel. This guarantees the channel (capacity=1) fills up.
        let logger = AuditLogger::new(
            pausing_sink,
            make_hasher(),
            1,                        // flush after every event
            Duration::from_secs(300), // long interval
            1,                        // minimal queue
            OverflowPolicy::BlockWithTimeout(Duration::from_millis(10)),
        );

        // First event goes into the channel and triggers a flush that blocks
        logger
            .log(AuditEventBuilder::new(AuditAction::Encrypt).table("t"))
            .await
            .unwrap();

        // Give the flush task time to pick up the event and block on PausingSink
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now the channel should be drained but the flush task is blocked in
        // write_batch. Send another event to fill the channel.
        logger
            .log(AuditEventBuilder::new(AuditAction::Encrypt).table("t"))
            .await
            .unwrap();

        // This third event should time out because the channel is full and the
        // flush task is blocked.
        let result = logger
            .log(AuditEventBuilder::new(AuditAction::Encrypt).table("t"))
            .await;

        assert!(
            matches!(result, Err(Error::AuditQueueFull)),
            "expected AuditQueueFull error, got {:?}",
            result,
        );

        // Unblock the sink so shutdown can complete
        pause.notify_one();
        logger.shutdown().await;
    }

    /// A sink that blocks on the first write_batch until notified, then
    /// passes through subsequent calls without blocking.
    struct PausingSink {
        pause: Arc<Notify>,
        inner: Arc<InMemoryAuditSink>,
        paused_once: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl AuditSink for PausingSink {
        async fn write_batch(&self, events: Vec<AuditEvent>) -> Result<(), Error> {
            // Only block on the first call
            if !self.paused_once.swap(true, Ordering::SeqCst) {
                self.pause.notified().await;
            }
            self.inner.write_batch(events).await
        }
    }

    #[tokio::test]
    async fn in_memory_sink_basics() {
        let sink = InMemoryAuditSink::new();
        assert!(sink.is_empty());
        assert_eq!(sink.len(), 0);
        assert!(sink.events().is_empty());

        let hasher = HmacEventHasher::new(SecretKey::from_bytes([0x42; 32]));
        let event = AuditEventBuilder::new(AuditAction::KeyCreate)
            .table("keys")
            .build(&hasher, None);

        sink.write_batch(vec![event]).await.unwrap();
        assert!(!sink.is_empty());
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.events()[0].action, AuditAction::KeyCreate);
    }
}
