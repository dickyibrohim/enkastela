//! LRU + TTL key cache.
//!
//! Caches decrypted DEKs in memory to avoid repeated database lookups.
//! Keys are evicted when their TTL expires or when the cache exceeds max entries (LRU).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::crypto::secret::SecretKey;

/// An entry in the key cache.
struct CacheEntry {
    key: SecretKey,
    inserted_at: Instant,
}

/// Thread-safe LRU + TTL cache for encryption keys.
pub struct KeyCache {
    entries: DashMap<String, CacheEntry>,
    lru_order: Mutex<VecDeque<String>>,
    ttl: Duration,
    max_entries: usize,
}

impl KeyCache {
    /// Creates a new key cache.
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            lru_order: Mutex::new(VecDeque::new()),
            ttl,
            max_entries,
        }
    }

    /// Gets a cached key by ID, returning a copy of the key bytes.
    ///
    /// Returns `None` if the key is not cached or has expired.
    pub fn get(&self, key_id: &str) -> Option<SecretKey> {
        let entry = self.entries.get(key_id)?;

        // Check TTL
        if entry.inserted_at.elapsed() > self.ttl {
            drop(entry);
            self.entries.remove(key_id);
            return None;
        }

        // Copy key bytes (we can't clone SecretKey, so rebuild from bytes)
        let key = SecretKey::from_bytes(*entry.key.as_bytes());

        // Update LRU order
        if let Ok(mut order) = self.lru_order.lock() {
            if let Some(pos) = order.iter().position(|id| id == key_id) {
                order.remove(pos);
            }
            order.push_back(key_id.to_string());
        }

        Some(key)
    }

    /// Inserts a key into the cache.
    ///
    /// If the cache exceeds max_entries, the least-recently-used entry is evicted.
    pub fn insert(&self, key_id: String, key: SecretKey) {
        // Evict expired entries first
        self.evict_expired();

        // Evict LRU if over capacity
        if let Ok(mut order) = self.lru_order.lock() {
            while self.entries.len() >= self.max_entries {
                if let Some(oldest) = order.pop_front() {
                    self.entries.remove(&oldest);
                } else {
                    break;
                }
            }

            // Remove existing entry from LRU order if present
            if let Some(pos) = order.iter().position(|id| id == &key_id) {
                order.remove(pos);
            }
            order.push_back(key_id.clone());
        }

        self.entries.insert(
            key_id,
            CacheEntry {
                key,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Returns the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all entries from the cache.
    pub fn clear(&self) {
        self.entries.clear();
        if let Ok(mut order) = self.lru_order.lock() {
            order.clear();
        }
    }

    /// Evicts entries that have exceeded their TTL.
    fn evict_expired(&self) {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| entry.value().inserted_at.elapsed() > self.ttl)
            .map(|entry| entry.key().clone())
            .collect();

        for key_id in expired {
            self.entries.remove(&key_id);
            if let Ok(mut order) = self.lru_order.lock() {
                if let Some(pos) = order.iter().position(|id| id == &key_id) {
                    order.remove(pos);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(byte: u8) -> SecretKey {
        SecretKey::from_bytes([byte; 32])
    }

    #[test]
    fn insert_and_get() {
        let cache = KeyCache::new(Duration::from_secs(60), 100);
        cache.insert("dek:users:v1".into(), make_key(0x01));
        let k = cache.get("dek:users:v1").unwrap();
        assert_eq!(k.as_bytes(), &[0x01; 32]);
    }

    #[test]
    fn get_missing_returns_none() {
        let cache = KeyCache::new(Duration::from_secs(60), 100);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn ttl_expiry() {
        let cache = KeyCache::new(Duration::from_millis(1), 100);
        cache.insert("key".into(), make_key(0x01));
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("key").is_none());
    }

    #[test]
    fn lru_eviction() {
        let cache = KeyCache::new(Duration::from_secs(60), 3);
        cache.insert("a".into(), make_key(0x01));
        cache.insert("b".into(), make_key(0x02));
        cache.insert("c".into(), make_key(0x03));

        // Cache is full (3). Insert "d" should evict "a" (LRU).
        cache.insert("d".into(), make_key(0x04));

        assert!(cache.get("a").is_none(), "a should be evicted");
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
        assert!(cache.get("d").is_some());
    }

    #[test]
    fn access_refreshes_lru() {
        let cache = KeyCache::new(Duration::from_secs(60), 3);
        cache.insert("a".into(), make_key(0x01));
        cache.insert("b".into(), make_key(0x02));
        cache.insert("c".into(), make_key(0x03));

        // Access "a" to refresh it
        let _ = cache.get("a");

        // Insert "d" — should evict "b" (now LRU), not "a"
        cache.insert("d".into(), make_key(0x04));

        assert!(cache.get("a").is_some(), "a was accessed, should survive");
        assert!(cache.get("b").is_none(), "b should be evicted");
    }

    #[test]
    fn clear_empties_cache() {
        let cache = KeyCache::new(Duration::from_secs(60), 100);
        cache.insert("a".into(), make_key(0x01));
        cache.insert("b".into(), make_key(0x02));
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.get("a").is_none());
    }
}
