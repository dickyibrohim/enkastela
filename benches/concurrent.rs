use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

use enkastela::crypto::{aead, kdf, secret::SecretKey};
use enkastela::keyring::cache::KeyCache;

fn bench_concurrent_cache_reads(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);
    let cache = Arc::new(KeyCache::new(Duration::from_secs(300), 10_000));

    // Pre-populate
    for i in 0..100 {
        let salt = [0x01; 32];
        let info = kdf::build_info("dek", &format!("table_{i}"), 1);
        let key = kdf::derive_key(&master, &salt, &info).unwrap();
        cache.insert(format!("dek:table_{i}:1"), key);
    }

    let mut group = c.benchmark_group("concurrent_cache_reads");
    for threads in [1, 4, 8] {
        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &nthreads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..nthreads {
                            let cache = Arc::clone(&cache);
                            s.spawn(move || {
                                for i in 0..100 {
                                    let key_id = format!("dek:table_{}:1", (t * 100 + i) % 100);
                                    black_box(cache.get(&key_id));
                                }
                            });
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_concurrent_encrypt(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);
    let salt = [0x01; 32];

    let mut group = c.benchmark_group("concurrent_encrypt");
    for threads in [1, 4, 8] {
        // Derive a key for each "table"
        let keys: Vec<SecretKey> = (0..threads)
            .map(|i| {
                let info = kdf::build_info("dek", &format!("table_{i}"), 1);
                kdf::derive_key(&master, &salt, &info).unwrap()
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(threads),
            &threads,
            |b, &_nthreads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for (t, key) in keys.iter().enumerate() {
                            let aad = format!("table_{t}:col");
                            s.spawn(move || {
                                let plaintext = vec![0xAB; 256];
                                for _ in 0..50 {
                                    black_box(
                                        aead::encrypt(
                                            black_box(key),
                                            black_box(&plaintext),
                                            black_box(aad.as_bytes()),
                                        )
                                        .unwrap(),
                                    );
                                }
                            });
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_concurrent_mixed_read_write_cache(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);

    c.bench_function("concurrent_mixed_cache_ops", |b| {
        b.iter(|| {
            let cache = Arc::new(KeyCache::new(Duration::from_secs(300), 1_000));
            std::thread::scope(|s| {
                // Writers
                for w in 0..2 {
                    let cache = Arc::clone(&cache);
                    let master_ref = &master;
                    s.spawn(move || {
                        for i in 0..50 {
                            let salt = [0x01; 32];
                            let info = kdf::build_info("dek", &format!("w{w}_t{i}"), 1);
                            let key = kdf::derive_key(master_ref, &salt, &info).unwrap();
                            cache.insert(format!("dek:w{w}_t{i}:1"), key);
                        }
                    });
                }
                // Readers
                for _ in 0..4 {
                    let cache = Arc::clone(&cache);
                    s.spawn(move || {
                        for i in 0..100 {
                            black_box(cache.get(&format!("dek:w0_t{}:1", i % 50)));
                        }
                    });
                }
            });
        });
    });
}

criterion_group!(
    benches,
    bench_concurrent_cache_reads,
    bench_concurrent_encrypt,
    bench_concurrent_mixed_read_write_cache,
);
criterion_main!(benches);
