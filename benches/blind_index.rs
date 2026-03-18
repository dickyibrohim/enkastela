use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

use enkastela::crypto::{hmac, secret::SecretKey};

fn bench_blind_index_compute(c: &mut Criterion) {
    let key = SecretKey::from_bytes([0xBB; 32]);
    let context = b"users:email";

    let mut group = c.benchmark_group("blind_index_compute");
    for size in [8, 32, 64, 256, 1024] {
        let data = vec![0xAA; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| {
                black_box(
                    hmac::compute_blind_index(black_box(&key), black_box(d), black_box(context))
                        .unwrap(),
                );
            });
        });
    }
    group.finish();
}

fn bench_blind_index_email(c: &mut Criterion) {
    let key = SecretKey::from_bytes([0xBB; 32]);
    let context = b"users:email";
    let email = b"alice@example.com";

    c.bench_function("blind_index_email", |b| {
        b.iter(|| {
            black_box(
                hmac::compute_blind_index(black_box(&key), black_box(email), black_box(context))
                    .unwrap(),
            );
        });
    });
}

fn bench_blind_index_different_contexts(c: &mut Criterion) {
    let key = SecretKey::from_bytes([0xBB; 32]);
    let data = b"test_data_here";
    let contexts: Vec<&[u8]> = vec![
        b"users:email",
        b"users:phone",
        b"orders:customer_email",
        b"payments:card_number",
    ];

    let mut group = c.benchmark_group("blind_index_contexts");
    for (i, ctx) in contexts.iter().enumerate() {
        group.bench_with_input(BenchmarkId::from_parameter(i), ctx, |b, c| {
            b.iter(|| {
                black_box(
                    hmac::compute_blind_index(black_box(&key), black_box(data), black_box(c))
                        .unwrap(),
                );
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_blind_index_compute,
    bench_blind_index_email,
    bench_blind_index_different_contexts,
);
criterion_main!(benches);
