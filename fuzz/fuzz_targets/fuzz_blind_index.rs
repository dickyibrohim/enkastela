#![no_main]

use libfuzzer_sys::fuzz_target;

use enkastela::crypto::hmac;
use enkastela::crypto::secret::SecretKey;

fuzz_target!(|data: &[u8]| {
    let key = SecretKey::from_bytes([0x42; 32]);
    let context = b"fuzz:column";

    // Computing a blind index on arbitrary data must never panic.
    let h1 = hmac::compute_blind_index(&key, data, context).unwrap();
    let h2 = hmac::compute_blind_index(&key, data, context).unwrap();

    // Must be deterministic
    assert_eq!(h1, h2);
    // Must be 32 bytes
    assert_eq!(h1.len(), 32);
});
