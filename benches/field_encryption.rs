use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

use enkastela::crypto::{aead, kdf, secret::SecretKey};
use enkastela::storage::codec::WirePayload;

fn bench_encrypt_field_pipeline(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);
    let salt = [0x01; 32];
    let info = kdf::build_info("dek", "users", 1);
    let dek = kdf::derive_key(&master, &salt, &info).unwrap();
    let aad = b"users:email";

    let mut group = c.benchmark_group("field_encrypt_pipeline");
    for size in [16, 64, 256, 1024, 4096] {
        let plaintext = vec![0xAB; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                let raw = aead::encrypt(black_box(&dek), black_box(pt), black_box(aad)).unwrap();
                let payload = WirePayload::new(1, raw);
                black_box(payload.encode());
            });
        });
    }
    group.finish();
}

fn bench_decrypt_field_pipeline(c: &mut Criterion) {
    let master = SecretKey::from_bytes([0x42; 32]);
    let salt = [0x01; 32];
    let info = kdf::build_info("dek", "users", 1);
    let dek = kdf::derive_key(&master, &salt, &info).unwrap();
    let aad = b"users:email";

    let mut group = c.benchmark_group("field_decrypt_pipeline");
    for size in [16, 64, 256, 1024, 4096] {
        let plaintext = vec![0xAB; size];
        let raw = aead::encrypt(&dek, &plaintext, aad).unwrap();
        let wire = WirePayload::new(1, raw).encode();
        group.bench_with_input(BenchmarkId::from_parameter(size), &wire, |b, w| {
            b.iter(|| {
                let payload = WirePayload::decode(black_box(w)).unwrap();
                black_box(aead::decrypt(&dek, &payload.raw_ciphertext, aad).unwrap());
            });
        });
    }
    group.finish();
}

fn bench_wire_format_encode(c: &mut Criterion) {
    let raw = vec![0xAB; 256 + 12 + 16]; // nonce + ct + tag
    c.bench_function("wire_format_encode_256", |b| {
        b.iter(|| {
            let payload = WirePayload::new(1, raw.clone());
            black_box(payload.encode());
        });
    });
}

fn bench_wire_format_decode(c: &mut Criterion) {
    let raw = vec![0xAB; 256 + 12 + 16];
    let wire = WirePayload::new(1, raw).encode();
    c.bench_function("wire_format_decode_256", |b| {
        b.iter(|| {
            black_box(WirePayload::decode(black_box(&wire)).unwrap());
        });
    });
}

criterion_group!(
    benches,
    bench_encrypt_field_pipeline,
    bench_decrypt_field_pipeline,
    bench_wire_format_encode,
    bench_wire_format_decode,
);
criterion_main!(benches);
