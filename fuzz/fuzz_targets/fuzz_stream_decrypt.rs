#![no_main]

use libfuzzer_sys::fuzz_target;

use enkastela::crypto::secret::SecretKey;
use enkastela::crypto::stream;

fuzz_target!(|data: &[u8]| {
    // Decrypting arbitrary bytes as a stream must never panic.
    let key = SecretKey::from_bytes([0x42; 32]);
    let _ = stream::decrypt_stream(&key, data, b"fuzz:aad");
    let _ = stream::decrypt_stream(&key, data, b"");
});
