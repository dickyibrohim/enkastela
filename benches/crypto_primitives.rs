use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

use enkastela::crypto::{aead, hmac, kdf, nonce, secret::SecretKey, wrap};

fn bench_aes256gcm_encrypt(c: &mut Criterion) {
    let key = SecretKey::from_bytes([0x42; 32]);
    let aad = b"users:email";

    let mut group = c.benchmark_group("aes256gcm_encrypt");
    for size in [32, 256, 1024, 4096, 16384] {
        let plaintext = vec![0xAB; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| aead::encrypt(black_box(&key), black_box(pt), black_box(aad)).unwrap());
        });
    }
    group.finish();
}

fn bench_aes256gcm_decrypt(c: &mut Criterion) {
    let key = SecretKey::from_bytes([0x42; 32]);
    let aad = b"users:email";

    let mut group = c.benchmark_group("aes256gcm_decrypt");
    for size in [32, 256, 1024, 4096, 16384] {
        let plaintext = vec![0xAB; size];
        let ciphertext = aead::encrypt(&key, &plaintext, aad).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            b.iter(|| aead::decrypt(black_box(&key), black_box(ct), black_box(aad)).unwrap());
        });
    }
    group.finish();
}

fn bench_hkdf_derive(c: &mut Criterion) {
    let key = SecretKey::from_bytes([0x42; 32]);
    let salt = [0x01; 32];
    let info = b"enkastela:dek:users:1";

    c.bench_function("hkdf_derive_key", |b| {
        b.iter(|| kdf::derive_key(black_box(&key), black_box(&salt), black_box(info)).unwrap());
    });
}

fn bench_key_wrap(c: &mut Criterion) {
    let wk = SecretKey::from_bytes([0x42; 32]);
    let dek = SecretKey::from_bytes([0x07; 32]);
    let wrapped = wrap::wrap_key(&wk, &dek).unwrap();

    c.bench_function("aes_key_wrap", |b| {
        b.iter(|| wrap::wrap_key(black_box(&wk), black_box(&dek)).unwrap());
    });
    c.bench_function("aes_key_unwrap", |b| {
        b.iter(|| wrap::unwrap_key(black_box(&wk), black_box(&wrapped)).unwrap());
    });
}

fn bench_hmac_blind_index(c: &mut Criterion) {
    let key = SecretKey::from_bytes([0xBB; 32]);
    let data = b"alice@example.com";
    let context = b"users:email";

    c.bench_function("hmac_blind_index", |b| {
        b.iter(|| {
            hmac::compute_blind_index(black_box(&key), black_box(data), black_box(context)).unwrap()
        });
    });
}

fn bench_nonce_generation(c: &mut Criterion) {
    c.bench_function("nonce_generate", |b| {
        b.iter(nonce::generate_nonce);
    });
}

criterion_group!(
    benches,
    bench_aes256gcm_encrypt,
    bench_aes256gcm_decrypt,
    bench_hkdf_derive,
    bench_key_wrap,
    bench_hmac_blind_index,
    bench_nonce_generation,
);
criterion_main!(benches);
