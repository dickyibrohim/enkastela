#![no_main]

use libfuzzer_sys::fuzz_target;

use enkastela::crypto::aead;
use enkastela::crypto::secret::SecretKey;

fuzz_target!(|data: &[u8]| {
    // Decrypting arbitrary bytes must never panic — only return Ok or Err.
    let key = SecretKey::from_bytes([0x42; 32]);
    let aad = b"fuzz:test";

    // Try decrypting raw bytes
    let _ = aead::decrypt(&key, data, aad);

    // Try decrypting with different AAD
    let _ = aead::decrypt(&key, data, b"");
    let _ = aead::decrypt(&key, data, data);
});
