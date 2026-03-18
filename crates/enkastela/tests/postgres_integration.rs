//! End-to-end integration tests against a real PostgreSQL database.
//!
//! These tests require a running PostgreSQL instance. Set the `TEST_DATABASE_URL`
//! environment variable or rely on the default (`postgres://localhost/enkastela_test`).
//!
//! Run with: `cargo test -p enkastela --test postgres_integration -- --ignored --test-threads=1`

use std::sync::Arc;
use std::time::Duration;

use enkastela::crypto::secret::SecretKey;
use enkastela::storage::repository::{KeyPurpose, KeyRepository, PostgresKeyRepository};
use enkastela::Vault;

/// Get the test database URL, falling back to a local default.
fn database_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/enkastela_test".into())
}

/// Helper: create a test master key.
fn test_key() -> SecretKey {
    SecretKey::from_bytes([0x42; 32])
}

/// Helper: clean the enkastela schema before each test.
async fn clean_schema(pool: &sqlx::PgPool) {
    let _ = sqlx::query("DROP SCHEMA IF EXISTS enkastela CASCADE")
        .execute(pool)
        .await;
}

/// Helper: build a vault connected to the test database.
async fn build_test_vault() -> Vault {
    Vault::builder()
        .database_url(&database_url())
        .master_key_static(test_key())
        .allow_insecure_connection()
        .run_migrations()
        .build()
        .await
        .expect("failed to build vault with PostgreSQL")
}

// -----------------------------------------------------------------------
// Migration tests
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn migrations_create_schema_and_tables() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;

    enkastela::storage::migrations::run_all(&pool)
        .await
        .expect("migrations failed");

    // Verify tables exist
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'enkastela'",
    )
    .fetch_one(&pool)
    .await
    .expect("query failed");

    assert!(row.0 >= 4, "expected at least 4 tables, got {}", row.0);

    pool.close().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn migrations_are_idempotent() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;

    // Run twice — should not fail
    enkastela::storage::migrations::run_all(&pool)
        .await
        .expect("first run");
    enkastela::storage::migrations::run_all(&pool)
        .await
        .expect("second run should be idempotent");

    pool.close().await;
}

// -----------------------------------------------------------------------
// Key Repository tests (PostgreSQL-backed)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn postgres_repo_store_and_retrieve_key() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    enkastela::storage::migrations::run_all(&pool)
        .await
        .expect("migrations");

    let repo = PostgresKeyRepository::new(pool.clone());

    let entry = enkastela::storage::repository::KeyEntry {
        id: "test-key-1".into(),
        purpose: KeyPurpose::Dek,
        table_name: Some("users".into()),
        column_name: Some("email".into()),
        version: 1,
        wrapped_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
        salt: vec![0xCA, 0xFE, 0xBA, 0xBE],
        algorithm: "aes-256-gcm".into(),
        status: enkastela::storage::repository::KeyStatus::Active,
        created_at: chrono::Utc::now(),
        rotated_at: None,
        destroyed_at: None,
    };

    repo.store_key(entry).await.expect("store_key");

    let retrieved = repo
        .get_key("users", 1, KeyPurpose::Dek)
        .await
        .expect("get_key")
        .expect("key should exist");

    assert_eq!(retrieved.id, "test-key-1");
    assert_eq!(retrieved.wrapped_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    pool.close().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn postgres_repo_destroy_key_zeros_material() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    enkastela::storage::migrations::run_all(&pool)
        .await
        .expect("migrations");

    let repo = PostgresKeyRepository::new(pool.clone());

    let entry = enkastela::storage::repository::KeyEntry {
        id: "destroy-test".into(),
        purpose: KeyPurpose::Dek,
        table_name: Some("orders".into()),
        column_name: None,
        version: 1,
        wrapped_key: vec![0xFF; 32],
        salt: vec![0xAA; 32],
        algorithm: "aes-256-gcm".into(),
        status: enkastela::storage::repository::KeyStatus::Active,
        created_at: chrono::Utc::now(),
        rotated_at: None,
        destroyed_at: None,
    };

    repo.store_key(entry).await.expect("store");
    repo.destroy_key("destroy-test").await.expect("destroy");

    let destroyed = repo
        .get_key("orders", 1, KeyPurpose::Dek)
        .await
        .expect("get")
        .expect("entry should still exist");

    assert_eq!(
        destroyed.status,
        enkastela::storage::repository::KeyStatus::Destroyed
    );
    assert!(destroyed.destroyed_at.is_some());
    // Verify key material is zeroed (single \x00 byte)
    assert!(
        destroyed.wrapped_key.iter().all(|b| *b == 0),
        "wrapped_key should be zeroed"
    );

    pool.close().await;
}

// -----------------------------------------------------------------------
// Vault end-to-end tests
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_encrypt_decrypt_roundtrip_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let ct = vault
        .encrypt_field("users", "email", b"alice@example.com")
        .await
        .expect("encrypt");

    assert!(Vault::is_encrypted(&ct));

    let pt = vault
        .decrypt_field("users", "email", &ct)
        .await
        .expect("decrypt");

    assert_eq!(&*pt, b"alice@example.com");

    vault.shutdown().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_deterministic_roundtrip_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let ct1 = vault
        .encrypt_field_deterministic("users", "ssn", b"123-45-6789")
        .await
        .expect("encrypt 1");

    let ct2 = vault
        .encrypt_field_deterministic("users", "ssn", b"123-45-6789")
        .await
        .expect("encrypt 2");

    // Deterministic: same input → same output
    assert_eq!(ct1, ct2);

    let pt = vault
        .decrypt_field_deterministic("users", "ssn", &ct1)
        .await
        .expect("decrypt");
    assert_eq!(&*pt, b"123-45-6789");

    vault.shutdown().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_blind_index_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let h1 = vault
        .compute_blind_index("users", "email", b"alice@example.com")
        .expect("blind index 1");

    let h2 = vault
        .compute_blind_index("users", "email", b"alice@example.com")
        .expect("blind index 2");

    assert_eq!(h1, h2, "blind index should be deterministic");

    let h3 = vault
        .compute_blind_index("users", "email", b"bob@example.com")
        .expect("blind index 3");

    assert_ne!(h1, h3, "different input should produce different index");

    vault.shutdown().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_keys_persisted_in_database() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    // Encrypt to trigger key creation
    let _ct = vault
        .encrypt_field("products", "name", b"Widget")
        .await
        .expect("encrypt");

    // Check that the key entry was stored in the database
    let repo = vault.repository().expect("should have repository");
    let key = repo
        .get_active_key("products", KeyPurpose::Dek)
        .await
        .expect("get_active_key");

    assert!(key.is_some(), "DEK should be persisted in the database");
    let key = key.unwrap();
    assert_eq!(key.table_name.as_deref(), Some("products"));
    assert!(!key.wrapped_key.is_empty());

    vault.shutdown().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_dek_salt_shared_across_instances() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    // Build vault 1 and encrypt
    let vault1 = build_test_vault().await;
    let ct = vault1
        .encrypt_field("shared_test", "data", b"shared secret")
        .await
        .expect("encrypt on vault 1");
    vault1.shutdown().await;

    // Build vault 2 (same DB, same master key) and decrypt
    let vault2 = build_test_vault().await;
    let pt = vault2
        .decrypt_field("shared_test", "data", &ct)
        .await
        .expect("decrypt on vault 2 should work because DEK salt is shared via DB");

    assert_eq!(&*pt, b"shared secret");

    vault2.shutdown().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_audit_events_persisted_to_database() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    // Encrypt a few fields to generate audit events
    for i in 0..3 {
        vault
            .encrypt_field("audit_test", "field", format!("value_{i}").as_bytes())
            .await
            .expect("encrypt");
    }

    // Shutdown flushes audit events
    vault.shutdown().await;

    // Give a moment for the flush to complete
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Verify audit events are in the database
    let verify_pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect for verification");

    let count = enkastela::audit::logger::count_audit_events(&verify_pool)
        .await
        .expect("count audit events");

    assert!(
        count >= 3,
        "expected at least 3 audit events in DB, got {count}"
    );

    verify_pool.close().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_wrong_table_decrypt_fails_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let ct = vault
        .encrypt_field("users", "email", b"secret")
        .await
        .expect("encrypt");

    let result = vault.decrypt_field("orders", "email", &ct).await;
    assert!(result.is_err(), "decrypting with wrong table should fail");

    vault.shutdown().await;
}

#[tokio::test]
#[ignore] // requires running PostgreSQL
async fn vault_health_check_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let health = vault.health_check();
    assert_eq!(
        health.overall,
        enkastela::observability::health::Health::Healthy
    );

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Batch encrypt/decrypt (Phase 1E)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_batch_encrypt_decrypt_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let items = vec![
        enkastela::vault::BatchItem::new("users", "email", b"alice@example.com"),
        enkastela::vault::BatchItem::new("users", "email", b"bob@example.com"),
        enkastela::vault::BatchItem::new("orders", "address", b"123 Main St"),
    ];

    let encrypted = vault.encrypt_batch(items).await;
    assert_eq!(encrypted.len(), 3);
    for res in &encrypted {
        assert!(res.is_ok(), "batch encrypt should succeed");
    }

    let decrypt_items: Vec<_> = encrypted
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let ct = r.as_ref().unwrap();
            let (table, column) = if i < 2 {
                ("users", "email")
            } else {
                ("orders", "address")
            };
            enkastela::vault::DecryptItem::new(table, column, ct)
        })
        .collect();

    let decrypted = vault.decrypt_batch(decrypt_items).await;
    assert_eq!(decrypted.len(), 3);
    assert_eq!(
        decrypted[0].as_ref().unwrap().as_slice(),
        b"alice@example.com"
    );
    assert_eq!(
        decrypted[1].as_ref().unwrap().as_slice(),
        b"bob@example.com"
    );
    assert_eq!(decrypted[2].as_ref().unwrap().as_slice(), b"123 Main St");

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Streaming encryption (Phase 1F)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_streaming_encrypt_decrypt_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    // 1 MiB payload
    let large_data = vec![0xABu8; 1024 * 1024];
    let chunk_size = 64 * 1024; // 64 KiB chunks

    let encrypted = vault
        .encrypt_stream("files", "content", &large_data, chunk_size)
        .await
        .expect("stream encrypt");

    assert!(
        encrypted.len() > large_data.len(),
        "encrypted should be larger"
    );

    let decrypted = vault
        .decrypt_stream("files", "content", &encrypted)
        .await
        .expect("stream decrypt");

    assert_eq!(decrypted.as_slice(), &large_data[..]);

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// ORE blind index (Phase 2B)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_ore_ordering_preserved_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let dek = enkastela::crypto::kdf::derive_key(&test_key(), b"ages", b"ore").unwrap();

    let ore_18 = enkastela::crypto::ore::ore_encrypt(&dek, &[18]).unwrap();
    let ore_21 = enkastela::crypto::ore::ore_encrypt(&dek, &[21]).unwrap();
    let ore_65 = enkastela::crypto::ore::ore_encrypt(&dek, &[65]).unwrap();

    assert_eq!(
        enkastela::crypto::ore::ore_compare(&dek, &ore_18, &ore_21),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        enkastela::crypto::ore::ore_compare(&dek, &ore_21, &ore_65),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        enkastela::crypto::ore::ore_compare(&dek, &ore_21, &ore_21),
        std::cmp::Ordering::Equal
    );

    // Serialize/deserialize roundtrip
    let bytes = enkastela::crypto::ore::ore_to_bytes(&ore_21);
    let restored = enkastela::crypto::ore::ore_from_bytes(&bytes).unwrap();
    assert_eq!(
        enkastela::crypto::ore::ore_compare(&dek, &ore_21, &restored),
        std::cmp::Ordering::Equal
    );

    // Store ORE ciphertext in PostgreSQL BYTEA
    let ore_bytes = enkastela::crypto::ore::ore_to_bytes(&ore_21);
    sqlx::query("CREATE TABLE IF NOT EXISTS ore_test (id SERIAL, age_ore BYTEA)")
        .execute(vault.pool().unwrap())
        .await
        .expect("create table");

    sqlx::query("INSERT INTO ore_test (age_ore) VALUES ($1)")
        .bind(&ore_bytes)
        .execute(vault.pool().unwrap())
        .await
        .expect("insert ore");

    let row: (Vec<u8>,) = sqlx::query_as("SELECT age_ore FROM ore_test LIMIT 1")
        .fetch_one(vault.pool().unwrap())
        .await
        .expect("select ore");

    let loaded = enkastela::crypto::ore::ore_from_bytes(&row.0).unwrap();
    assert_eq!(
        enkastela::crypto::ore::ore_compare(&dek, &ore_21, &loaded),
        std::cmp::Ordering::Equal
    );

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Bloom filter blind index (Phase 2C)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_bloom_filter_search_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let bloom_key =
        enkastela::crypto::kdf::derive_key(&test_key(), b"bloom_salt", b"users.email.bloom")
            .unwrap();
    let config = enkastela::blind::bloom::BloomConfig::default();

    let doc_filter =
        enkastela::blind::bloom::compute_bloom_filter(&bloom_key, "alice@example.com", &config);
    let query_filter =
        enkastela::blind::bloom::compute_bloom_filter(&bloom_key, "example", &config);
    let no_match_filter =
        enkastela::blind::bloom::compute_bloom_filter(&bloom_key, "nomatch.xyz", &config);

    assert!(enkastela::blind::bloom::bloom_search(
        &doc_filter,
        &query_filter
    ));
    assert!(!enkastela::blind::bloom::bloom_search(
        &doc_filter,
        &no_match_filter
    ));

    // Store in PostgreSQL BYTEA
    let bloom_bytes = doc_filter.to_bytes();
    sqlx::query("CREATE TABLE IF NOT EXISTS bloom_test (id SERIAL, email_bloom BYTEA)")
        .execute(vault.pool().unwrap())
        .await
        .expect("create table");

    sqlx::query("INSERT INTO bloom_test (email_bloom) VALUES ($1)")
        .bind(&bloom_bytes)
        .execute(vault.pool().unwrap())
        .await
        .expect("insert bloom");

    let row: (Vec<u8>,) = sqlx::query_as("SELECT email_bloom FROM bloom_test LIMIT 1")
        .fetch_one(vault.pool().unwrap())
        .await
        .expect("select bloom");

    let loaded = enkastela::blind::bloom::BloomFilter::from_bytes(&row.0).unwrap();
    assert!(enkastela::blind::bloom::bloom_search(
        &loaded,
        &query_filter
    ));

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Encrypted JSONB (Phase 2D)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_encrypted_jsonb_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let dek =
        enkastela::crypto::kdf::derive_key(&test_key(), b"profiles_salt", b"profiles").unwrap();

    let mut json = serde_json::json!({
        "name": "Alice",
        "ssn": "123-45-6789",
        "address": {
            "street": "123 Main St",
            "city": "Springfield"
        }
    });

    let paths: Vec<&str> = vec!["/ssn", "/address/street"];
    enkastela::types::encrypted_json::encrypt_json_fields(&dek, &mut json, "profiles", 1, &paths)
        .expect("encrypt json fields");

    // SSN should now be an encrypted string
    let ssn_val = json.get("ssn").unwrap().as_str().unwrap();
    assert!(ssn_val.starts_with("ek:"), "ssn should be encrypted");

    // name should remain plaintext
    assert_eq!(json.get("name").unwrap().as_str().unwrap(), "Alice");

    // Store in PostgreSQL JSONB
    sqlx::query("CREATE TABLE IF NOT EXISTS json_test (id SERIAL, profile JSONB)")
        .execute(vault.pool().unwrap())
        .await
        .expect("create table");

    sqlx::query("INSERT INTO json_test (profile) VALUES ($1::jsonb)")
        .bind(&json)
        .execute(vault.pool().unwrap())
        .await
        .expect("insert jsonb");

    let row: (serde_json::Value,) = sqlx::query_as("SELECT profile FROM json_test LIMIT 1")
        .fetch_one(vault.pool().unwrap())
        .await
        .expect("select jsonb");

    let mut loaded = row.0;
    enkastela::types::encrypted_json::decrypt_json_fields(&dek, &mut loaded, "profiles", &paths)
        .expect("decrypt json fields");

    assert_eq!(loaded.get("ssn").unwrap().as_str().unwrap(), "123-45-6789");
    assert_eq!(
        loaded
            .get("address")
            .unwrap()
            .get("street")
            .unwrap()
            .as_str()
            .unwrap(),
        "123 Main St"
    );

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// SQL Firewall (Phase 3A)
// -----------------------------------------------------------------------

#[cfg(feature = "firewall")]
#[tokio::test]
#[ignore]
async fn vault_sql_firewall_detects_violations_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    vault
        .encrypt_field("users", "email", b"test@example.com")
        .await
        .expect("encrypt");

    let mut policy = enkastela::firewall::policy::FirewallPolicy::new();
    policy.add_encrypted_column("users", "email");

    // Plaintext comparison — VIOLATION
    let v1 = enkastela::firewall::analyzer::analyze_query(
        "SELECT * FROM users WHERE email = 'alice@test.com'",
        &policy,
    );
    assert!(!v1.is_empty(), "should detect plaintext comparison");

    // Parameterized — safe
    let v2 = enkastela::firewall::analyzer::analyze_query(
        "SELECT * FROM users WHERE email = $1",
        &policy,
    );
    assert!(v2.is_empty(), "parameterized should be safe");

    // LIKE on encrypted — VIOLATION
    let v3 = enkastela::firewall::analyzer::analyze_query(
        "SELECT * FROM users WHERE email LIKE '%@test%'",
        &policy,
    );
    assert!(!v3.is_empty(), "LIKE should be violation");

    // ORDER BY encrypted — VIOLATION
    let v4 =
        enkastela::firewall::analyzer::analyze_query("SELECT * FROM users ORDER BY email", &policy);
    assert!(!v4.is_empty(), "ORDER BY should be violation");

    // INSERT plaintext — VIOLATION
    let v5 = enkastela::firewall::analyzer::analyze_query(
        "INSERT INTO users (name, email) VALUES ('Alice', 'alice@test.com')",
        &policy,
    );
    assert!(!v5.is_empty(), "plaintext INSERT should be violation");

    // INSERT parameterized — safe
    let v6 = enkastela::firewall::analyzer::analyze_query(
        "INSERT INTO users (name, email) VALUES ($1, $2)",
        &policy,
    );
    assert!(v6.is_empty(), "parameterized INSERT should be safe");

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Intrusion Detection (Phase 3B)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_intrusion_detection_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let registry = Arc::new(enkastela::intrusion::poison::PoisonRegistry::new());
    registry.register(enkastela::intrusion::poison::PoisonRecord::new(
        "users",
        "email",
        "canary-001",
        b"canary@trap.internal",
    ));

    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestAlertHandler {
        count: Arc<AtomicU64>,
    }

    impl enkastela::intrusion::detector::AlertHandler for TestAlertHandler {
        fn handle_alert(&self, _alert: &enkastela::intrusion::detector::IntrusionAlert) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    let alert_count = Arc::new(AtomicU64::new(0));
    let mut detector = enkastela::intrusion::detector::IntrusionDetector::new(registry.clone());
    detector.add_handler(TestAlertHandler {
        count: alert_count.clone(),
    });

    // Non-canary — no alert
    assert!(!detector.check_access("users", "email", "canary-999"));
    assert_eq!(alert_count.load(Ordering::Relaxed), 0);

    // Canary — alert triggered
    assert!(detector.check_access("users", "email", "canary-001"));
    assert_eq!(alert_count.load(Ordering::Relaxed), 1);
    assert_eq!(detector.alert_count(), 1);

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Access Control (Phase 3C)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_access_control_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let mut policy = enkastela::access::policy::AccessPolicy::new();
    policy.grant_admin("admin");
    policy.grant(
        "support",
        "users",
        "name",
        enkastela::access::policy::Permission::Decrypt,
    );
    policy.grant(
        "support",
        "users",
        "ssn",
        enkastela::access::policy::Permission::Deny,
    );

    // Admin access
    assert!(policy.check(
        "admin",
        "users",
        "ssn",
        enkastela::access::policy::Permission::Decrypt
    ));

    // Support can decrypt name
    assert!(policy.check(
        "support",
        "users",
        "name",
        enkastela::access::policy::Permission::Decrypt
    ));

    // Support cannot decrypt ssn
    assert!(!policy.check(
        "support",
        "users",
        "ssn",
        enkastela::access::policy::Permission::Decrypt
    ));

    // Unknown role denied
    assert!(!policy.check(
        "viewer",
        "users",
        "name",
        enkastela::access::policy::Permission::Decrypt
    ));

    // Real encryption + access-gated decrypt
    let ct = vault
        .encrypt_field("users", "name", b"Alice Johnson")
        .await
        .expect("encrypt");

    let ctx = enkastela::access::context::AccessContext::new("support");
    if policy.check(
        &ctx.role,
        "users",
        "name",
        enkastela::access::policy::Permission::Decrypt,
    ) {
        let pt = vault
            .decrypt_field("users", "name", &ct)
            .await
            .expect("decrypt allowed");
        assert_eq!(&*pt, b"Alice Johnson");
    }

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Compliance Reporting (Phase 3D)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_compliance_reports_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let _vault = build_test_vault().await;

    // SOC2 — fully configured
    let config = enkastela::compliance::report::ReportConfig {
        audit_enabled: true,
        rotation_configured: true,
        tls_enforced: true,
        crypto_shredding: true,
        fips_mode: false,
        access_control: true,
    };
    let soc2 = enkastela::compliance::report::generate_report(
        enkastela::compliance::report::Standard::SOC2,
        &config,
    );
    assert_eq!(soc2.controls.len(), 5);
    assert_eq!(soc2.summary.implemented, 5);

    // GDPR
    let gdpr = enkastela::compliance::report::generate_report(
        enkastela::compliance::report::Standard::GDPR,
        &config,
    );
    assert!(gdpr.controls.len() >= 5);

    // HIPAA with FIPS
    let hipaa_config = enkastela::compliance::report::ReportConfig {
        fips_mode: true,
        ..config
    };
    let hipaa = enkastela::compliance::report::generate_report(
        enkastela::compliance::report::Standard::HIPAA,
        &hipaa_config,
    );
    assert_eq!(hipaa.summary.implemented, 5);

    // JSON roundtrip
    let json = serde_json::to_string_pretty(&soc2).unwrap();
    let _: enkastela::compliance::report::ComplianceReport = serde_json::from_str(&json).unwrap();
}

// -----------------------------------------------------------------------
// Multi-Master Key (Phase 3E)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_multi_master_key_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let key_prod = SecretKey::from_bytes([0xAA; 32]);
    let key_staging = SecretKey::from_bytes([0xBB; 32]);

    let mut hierarchy = enkastela::keyring::hierarchy::KeyHierarchy::new(
        "prod",
        enkastela::keyring::provider::StaticKeyProvider::new(SecretKey::from_bytes([0xAA; 32])),
    );
    hierarchy.add_provider(
        "staging",
        enkastela::keyring::provider::StaticKeyProvider::new(SecretKey::from_bytes([0xBB; 32])),
    );

    assert_eq!(hierarchy.primary_id(), "prod");
    let pk = hierarchy.get_primary_key().await.unwrap();
    assert_eq!(pk.as_bytes(), key_prod.as_bytes());

    hierarchy.set_primary("staging").unwrap();
    let sk = hierarchy.get_primary_key().await.unwrap();
    assert_eq!(sk.as_bytes(), key_staging.as_bytes());

    // Encrypt with prod key via Vault
    let vault = Vault::builder()
        .database_url(&database_url())
        .master_key_static(SecretKey::from_bytes([0xAA; 32]))
        .allow_insecure_connection()
        .run_migrations()
        .build()
        .await
        .expect("build vault");

    let ct = vault
        .encrypt_field("multi_test", "secret", b"multi-master")
        .await
        .expect("encrypt");

    let pt = vault
        .decrypt_field("multi_test", "secret", &ct)
        .await
        .expect("decrypt");
    assert_eq!(&*pt, b"multi-master");

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Metrics recording (Phase 4E)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_metrics_recorded_during_operations() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let metrics = vault.metrics();
    metrics.record_encrypt("users", "email", Duration::from_millis(1));
    metrics.record_decrypt("users", "email", Duration::from_millis(1));
    metrics.record_key_cache_hit();
    metrics.record_key_cache_miss();
    metrics.record_error("test");
    metrics.record_blind_index_compute("users", "email", Duration::from_micros(100));
    metrics.record_rotation_row("users");

    let ct = vault
        .encrypt_field("metrics_test", "data", b"hello metrics")
        .await
        .expect("encrypt");

    let _pt = vault
        .decrypt_field("metrics_test", "data", &ct)
        .await
        .expect("decrypt");

    vault.shutdown().await;
}

// -----------------------------------------------------------------------
// Crypto Backend (Phase 2A)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_crypto_backend_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let _vault = build_test_vault().await;

    let backend = enkastela::crypto::backend::default_backend();
    // Backend name depends on which features are enabled
    assert!(!backend.name().is_empty());

    let key = SecretKey::from_bytes([0x42; 32]);
    let ct = backend.aead_encrypt(&key, b"backend test", b"aad").unwrap();
    let pt = backend.aead_decrypt(&key, &ct, b"aad").unwrap();
    assert_eq!(&*pt, b"backend test");

    let mac1 = backend.hmac_sha256(&key, b"data", b"ctx").unwrap();
    let mac2 = backend.hmac_sha256(&key, b"data", b"ctx").unwrap();
    assert_eq!(mac1, mac2);

    let dk1 = backend.hkdf_derive(&key, b"s1", b"info").unwrap();
    let dk2 = backend.hkdf_derive(&key, b"s2", b"info").unwrap();
    assert_ne!(dk1.as_bytes(), dk2.as_bytes());
}

// -----------------------------------------------------------------------
// Re-encryption Pipeline (Phase 2E)
// -----------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn vault_reencryption_pipeline_with_postgres() {
    let pool = sqlx::PgPool::connect(&database_url())
        .await
        .expect("connect");
    clean_schema(&pool).await;
    pool.close().await;

    let vault = build_test_vault().await;

    let _ = sqlx::query("DROP TABLE IF EXISTS reencrypt_test")
        .execute(vault.pool().unwrap())
        .await;
    sqlx::query(
        "CREATE TABLE reencrypt_test (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL
        )",
    )
    .execute(vault.pool().unwrap())
    .await
    .expect("create table");

    for i in 0..10 {
        let ct = vault
            .encrypt_field(
                "reencrypt_test",
                "email",
                format!("user{i}@test.com").as_bytes(),
            )
            .await
            .expect("encrypt");
        sqlx::query("INSERT INTO reencrypt_test (email) VALUES ($1)")
            .bind(&ct)
            .execute(vault.pool().unwrap())
            .await
            .expect("insert");
    }

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM reencrypt_test")
        .fetch_one(vault.pool().unwrap())
        .await
        .expect("count");
    assert_eq!(count.0, 10);

    // Verify first row decrypts correctly
    let row: (String,) = sqlx::query_as("SELECT email FROM reencrypt_test WHERE id = 1")
        .fetch_one(vault.pool().unwrap())
        .await
        .expect("select");
    let pt = vault
        .decrypt_field("reencrypt_test", "email", &row.0)
        .await
        .expect("decrypt");
    assert_eq!(&*pt, b"user0@test.com");

    // Pipeline config
    let config = enkastela::rotation::pipeline::PipelineConfig {
        table: "reencrypt_test".into(),
        columns: vec!["email".into()],
        pk_column: "id".into(),
        batch_size: 5,
        from_version: 1,
        to_version: 2,
    };
    let pipeline = enkastela::rotation::pipeline::ReEncryptionPipeline::new(config);
    assert_eq!(
        pipeline.progress().status,
        enkastela::rotation::pipeline::PipelineStatus::Pending
    );
    // Initial query (no cursor yet) uses $1 as the limit parameter
    assert!(pipeline.next_batch_query().contains("LIMIT $1"));

    vault.shutdown().await;
}
