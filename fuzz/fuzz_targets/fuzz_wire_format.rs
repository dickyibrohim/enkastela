#![no_main]

use libfuzzer_sys::fuzz_target;

use enkastela::storage::codec::WirePayload;

fuzz_target!(|data: &[u8]| {
    // Decoding arbitrary bytes as a wire format string must never panic.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = WirePayload::decode(s);
    }

    // Also test with a valid prefix to exercise deeper parsing paths.
    if data.len() >= 4 {
        let with_prefix = format!(
            "ek:1:v1:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
        );
        let _ = WirePayload::decode(&with_prefix);
    }
});
