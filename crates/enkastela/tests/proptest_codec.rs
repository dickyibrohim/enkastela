//! Property-based tests for wire format codec.
//!
//! Verifies encode/decode roundtrip and robustness against random inputs.

use enkastela::storage::codec::WirePayload;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// For any valid payload, encode then decode must produce the original.
    #[test]
    fn codec_encode_decode_roundtrip(
        dek_version in 1..=u32::MAX,
        // Minimum ciphertext: nonce(12) + tag(16) = 28 bytes
        extra_len in 0..1024usize,
    ) {
        let raw = vec![0xABu8; 28 + extra_len];
        let payload = WirePayload::new(dek_version, raw);
        let encoded = payload.encode();
        let decoded = WirePayload::decode(&encoded).unwrap();
        prop_assert_eq!(decoded.format_version, payload.format_version);
        prop_assert_eq!(decoded.dek_version, payload.dek_version);
        prop_assert_eq!(&decoded.raw_ciphertext, &payload.raw_ciphertext);
    }

    /// Decoding random strings must never panic — it should return Ok or Err.
    #[test]
    fn codec_decode_random_never_panics(
        random_string in ".*",
    ) {
        let _ = WirePayload::decode(&random_string);
    }

    /// Decoding random bytes as UTF-8 must never panic.
    #[test]
    fn codec_decode_random_bytes_never_panics(
        random_bytes in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        if let Ok(s) = std::str::from_utf8(&random_bytes) {
            let _ = WirePayload::decode(s);
        }
    }

    /// Encoded output always starts with the "ek:" prefix.
    #[test]
    fn codec_encoded_starts_with_prefix(
        dek_version in 1..=1000u32,
        raw in prop::collection::vec(any::<u8>(), 28..128),
    ) {
        let payload = WirePayload::new(dek_version, raw);
        let encoded = payload.encode();
        prop_assert!(encoded.starts_with("ek:1:v"));
    }

    /// is_encrypted returns true for any encoded payload.
    #[test]
    fn codec_is_encrypted_for_encoded(
        dek_version in 1..=u32::MAX,
    ) {
        let raw = vec![0u8; 28];
        let payload = WirePayload::new(dek_version, raw);
        let encoded = payload.encode();
        prop_assert!(WirePayload::is_encrypted(&encoded));
    }
}
