use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

use enkastela::crypto::{kdf, secret::SecretKey};
use enkastela::keyring::cache::KeyCache;

fn bench_cache_insert(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);

    c.bench_function("cache_insert", |b| {
        let cache = KeyCache::new(Duration::from_secs(300), 10_000);
        let mut i = 0u64;
        b.iter(|| {
            let salt = [0x01; 32];
            let info = kdf::build_info("dek", &format!("table_{i}"), 1);
            let key = kdf::derive_key(&master, &salt, &info).unwrap();
            cache.insert(format!("dek:table_{i}:1"), key);
            i += 1;
        });
    });
}

fn bench_cache_hit(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);
    let cache = KeyCache::new(Duration::from_secs(300), 10_000);

    // Pre-populate cache
    for i in 0..100 {
        let salt = [0x01; 32];
        let info = kdf::build_info("dek", &format!("table_{i}"), 1);
        let key = kdf::derive_key(&master, &salt, &info).unwrap();
        cache.insert(format!("dek:table_{i}:1"), key);
    }

    c.bench_function("cache_hit", |b| {
        let mut i = 0u64;
        b.iter(|| {
            let key_id = format!("dek:table_{}:1", i % 100);
            black_box(cache.get(&key_id));
            i += 1;
        });
    });
}

fn bench_cache_miss(c: &mut Criterion) {
    let cache = KeyCache::new(Duration::from_secs(300), 10_000);

    c.bench_function("cache_miss", |b| {
        let mut i = 0u64;
        b.iter(|| {
            black_box(cache.get(&format!("nonexistent_{i}")));
            i += 1;
        });
    });
}

fn bench_cache_eviction(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);

    let mut group = c.benchmark_group("cache_eviction");
    for max_entries in [100, 500, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(max_entries),
            &max_entries,
            |b, &max| {
                b.iter(|| {
                    let cache = KeyCache::new(Duration::from_secs(300), max);
                    // Insert more than max to trigger LRU evictions
                    for i in 0..(max + 50) {
                        let salt = [0x01; 32];
                        let info = kdf::build_info("dek", &format!("t_{i}"), 1);
                        let key = kdf::derive_key(&master, &salt, &info).unwrap();
                        cache.insert(format!("dek:t_{i}:1"), key);
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_cache_insert,
    bench_cache_hit,
    bench_cache_miss,
    bench_cache_eviction,
);
criterion_main!(benches);
