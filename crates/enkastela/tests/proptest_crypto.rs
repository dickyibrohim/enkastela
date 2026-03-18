//! Property-based tests for cryptographic primitives.
//!
//! Uses `proptest` to verify invariants across a wide range of random inputs.

use enkastela::crypto::aead;
use enkastela::crypto::constant_time;
use enkastela::crypto::hmac;
use enkastela::crypto::kdf;
use enkastela::crypto::secret::SecretKey;
use enkastela::crypto::siv;
use enkastela::crypto::stream;
use proptest::prelude::*;

// --- AES-256-GCM roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn aead_encrypt_decrypt_roundtrip(
        key_bytes in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        aad in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let key = SecretKey::from_bytes(key_bytes);
        let ct = aead::encrypt(&key, &plaintext, &aad).unwrap();
        let pt = aead::decrypt(&key, &ct, &aad).unwrap();
        prop_assert_eq!(&*pt, &plaintext);
    }

    #[test]
    fn aead_different_keys_fail_decrypt(
        k1 in prop::array::uniform32(any::<u8>()),
        k2 in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        aad in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assume!(k1 != k2);
        let key1 = SecretKey::from_bytes(k1);
        let key2 = SecretKey::from_bytes(k2);
        let ct = aead::encrypt(&key1, &plaintext, &aad).unwrap();
        let result = aead::decrypt(&key2, &ct, &aad);
        prop_assert!(result.is_err());
    }

    #[test]
    fn aead_different_aad_fail_decrypt(
        key_bytes in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        aad1 in prop::collection::vec(any::<u8>(), 1..64),
        aad2 in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(aad1 != aad2);
        let key = SecretKey::from_bytes(key_bytes);
        let ct = aead::encrypt(&key, &plaintext, &aad1).unwrap();
        let result = aead::decrypt(&key, &ct, &aad2);
        prop_assert!(result.is_err());
    }
}

// --- AES-256-SIV roundtrip ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn siv_encrypt_decrypt_roundtrip(
        key_bytes in prop::collection::vec(any::<u8>(), 64..=64),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        aad in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let key_arr: [u8; 64] = key_bytes.try_into().unwrap();
        let ct = siv::encrypt_deterministic(&key_arr, &plaintext, &aad).unwrap();
        let pt = siv::decrypt_deterministic(&key_arr, &ct, &aad).unwrap();
        prop_assert_eq!(&*pt, &plaintext);
    }

    #[test]
    fn siv_deterministic_same_output(
        key_bytes in prop::collection::vec(any::<u8>(), 64..=64),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        aad in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let key_arr: [u8; 64] = key_bytes.try_into().unwrap();
        let ct1 = siv::encrypt_deterministic(&key_arr, &plaintext, &aad).unwrap();
        let ct2 = siv::encrypt_deterministic(&key_arr, &plaintext, &aad).unwrap();
        prop_assert_eq!(&ct1, &ct2, "SIV must be deterministic");
    }
}

// --- HKDF key derivation ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn kdf_same_inputs_same_output(
        master in prop::array::uniform32(any::<u8>()),
        salt in prop::array::uniform32(any::<u8>()),
        info in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let mk = SecretKey::from_bytes(master);
        let d1 = kdf::derive_key(&mk, &salt, &info).unwrap();
        let d2 = kdf::derive_key(&mk, &salt, &info).unwrap();
        prop_assert_eq!(d1.as_bytes(), d2.as_bytes());
    }

    #[test]
    fn kdf_different_salt_different_output(
        master in prop::array::uniform32(any::<u8>()),
        salt1 in prop::array::uniform32(any::<u8>()),
        salt2 in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(salt1 != salt2);
        let mk = SecretKey::from_bytes(master);
        let d1 = kdf::derive_key(&mk, &salt1, b"test").unwrap();
        let d2 = kdf::derive_key(&mk, &salt2, b"test").unwrap();
        prop_assert_ne!(d1.as_bytes(), d2.as_bytes());
    }
}

// --- HMAC blind index ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn hmac_deterministic(
        key_bytes in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 0..512),
        context in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = SecretKey::from_bytes(key_bytes);
        let h1 = hmac::compute_blind_index(&key, &data, &context).unwrap();
        let h2 = hmac::compute_blind_index(&key, &data, &context).unwrap();
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn hmac_output_is_32_bytes(
        key_bytes in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 0..512),
        context in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = SecretKey::from_bytes(key_bytes);
        let h = hmac::compute_blind_index(&key, &data, &context).unwrap();
        prop_assert_eq!(h.len(), 32);
    }
}

// --- Key wrapping ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn wrap_unwrap_roundtrip(
        wrapping_key_bytes in prop::array::uniform32(any::<u8>()),
        dek_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        use enkastela::crypto::wrap;
        let wk = SecretKey::from_bytes(wrapping_key_bytes);
        let dek = SecretKey::from_bytes(dek_bytes);
        let wrapped = wrap::wrap_key(&wk, &dek).unwrap();
        let unwrapped = wrap::unwrap_key(&wk, &wrapped).unwrap();
        prop_assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }
}

// --- Constant-time comparison ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn ct_eq_reflexive(
        data in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assert!(constant_time::ct_eq(&data, &data));
    }

    #[test]
    fn ct_eq_different_data(
        a in prop::collection::vec(any::<u8>(), 1..256),
        b in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        if a != b {
            prop_assert!(!constant_time::ct_eq(&a, &b));
        }
    }
}

// --- Streaming encryption ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn stream_roundtrip(
        key_bytes in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..8192),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        chunk_size in 16..512usize,
    ) {
        let key = SecretKey::from_bytes(key_bytes);
        let ct = stream::encrypt_stream(&key, &plaintext, &aad, chunk_size).unwrap();
        let pt = stream::decrypt_stream(&key, &ct, &aad).unwrap();
        prop_assert_eq!(&*pt, &plaintext);
    }

    #[test]
    fn stream_wrong_key_fails(
        k1 in prop::array::uniform32(any::<u8>()),
        k2 in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(k1 != k2);
        let key1 = SecretKey::from_bytes(k1);
        let key2 = SecretKey::from_bytes(k2);
        let ct = stream::encrypt_stream(&key1, &plaintext, b"aad", 64).unwrap();
        let result = stream::decrypt_stream(&key2, &ct, b"aad");
        prop_assert!(result.is_err());
    }
}
