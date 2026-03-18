# Enkastela

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-427%20passing-brightgreen.svg)](https://github.com/dickyibrohim/enkastela/actions)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/dickyibrohim/enkastela)

**Application-level field encryption for PostgreSQL. Written in Rust.**

---

## Why Enkastela?

PostgreSQL's Transparent Data Encryption (TDE) encrypts at the page level — it protects against disk theft but not against a compromised database connection, a malicious DBA, or application-level data leaks.

Enkastela encrypts individual fields at the application layer. The database never sees plaintext.

## Features

### Cryptographic Core

- **AES-256-GCM** authenticated encryption with per-field CSPRNG nonces
- **AES-256-SIV** deterministic encryption for unique constraints and exact-match lookups
- **HKDF-SHA256** key derivation with domain separation (`enkastela:{purpose}:{scope}:{version}`)
- **AES-256 Key Wrapping** (RFC 3394) for secure DEK storage
- **Constant-time comparison** via `subtle` crate for all tag/hash verification
- **Streaming encryption** — chunked AES-256-GCM for payloads exceeding 16 MiB
- **FIPS-140 backend** — optional `aws-lc-rs` cryptographic provider (feature flag: `fips`). Note: this uses the FIPS-validated module in aws-lc-rs, but Enkastela itself has not been independently validated

### Key Management

- **Per-table DEKs** — each table gets its own derived encryption key
- **LRU + TTL cache** — bounded in-memory key cache with `DashMap` for concurrent access
- **Key rotation engine** — lazy (on-read) and eager (background batch) strategies with progress tracking
- **Re-encryption pipeline** — cursor-based batch re-encryption with crash recovery
- **Multi-tenant isolation** — random per-tenant keys (not derived), wrapped with master key
- **Multi-master key hierarchy** — multiple providers per environment or compliance boundary
- **Key lifecycle** — `Active -> Rotating -> Retired -> Destroyed` with physical key material zeroing
- **Pluggable providers** — `MasterKeyProvider` trait for KMS integration

### Cloud KMS Integration

All KMS providers are optional feature flags. Core library works 100% standalone.

- **AWS KMS** — envelope encryption via `GenerateDataKey`/`Decrypt` (feature: `kms-aws`)
- **GCP Cloud KMS** — key wrapping via Cloud KMS encrypt API (feature: `kms-gcp`)
- **Azure Key Vault** — key wrap/unwrap via Key Vault REST API (feature: `kms-azure`)
- **HashiCorp Vault** — Transit secrets engine for data key generation (feature: `kms-hashicorp`)

### Searchable Encryption

- **HMAC-SHA256 blind indexes** for equality search on encrypted data
- **Unicode NFC normalization** — equivalent representations produce the same index
- **Compound blind indexes** — multi-field indexes with length-prefixed encoding
- **Truncatable indexes** — trade storage for false positive rate (minimum 8 bytes)
- **Order-Revealing Encryption (ORE)** — range queries (`WHERE age > 21`) without decryption (feature: `ore`)
- **Bloom filter blind indexes** — partial/prefix search via n-gram hashing (feature: `bloom`)

### Encrypted JSONB

- **Selective field encryption** within JSON objects using JSON Pointer (RFC 6901)
- Encrypt `{"name": "Alice", "ssn": "123"}` to `{"name": "Alice", "ssn": "ek:1:v1:..."}`
- Supports nested paths and array elements

### Security Features

- **SQL Firewall** — detect queries that bypass encryption (`SELECT` on encrypted columns, plaintext `INSERT`, etc.) (feature: `firewall`)
- **Intrusion detection** — poison/honeypot records that trigger alerts on unauthorized decryption (feature: `intrusion`)
- **Field-level access control** — role-based encrypt/decrypt permissions per table:column (feature: `access-control`)
- **Compliance report helpers** — generate control mapping reports for SOC2, GDPR, and HIPAA assessments (feature: `compliance`). These are reporting aids, not certifications

### GDPR Compliance

- **Crypto-shredding** — destroy a tenant key to make all their data permanently unrecoverable
- **Erasure receipts** — SHA-256 pre-destruction proof with constant-time verification
- **Data export** — JSON-serializable export for GDPR Article 20 data portability

### Audit Trail

- **Async batched logger** — bounded `mpsc` channel with configurable flush interval and batch size
- **HMAC hash chain** — tamper-evident integrity with chain verification
- **Configurable overflow** — block-with-timeout (fail-closed) or drop-and-count policies
- **Pluggable sink** — `AuditSink` trait for custom storage backends
- **Graceful shutdown** — flush pending events on Drop

### Observability

- **`MetricsRecorder` trait** — plug in Prometheus, StatsD, or any metrics system
- **Prometheus integration** — 12+ pre-built metrics (encrypt/decrypt duration, cache hit rate, rotation progress) (feature: `metrics-prometheus`)
- **OpenTelemetry integration** — vendor-agnostic telemetry with counters, histograms, and gauges (feature: `otel`)
- **Health checks** — aggregated subsystem health (cache, audit logger)
- **In-memory metrics** — built-in atomic counters for testing

### Batch Operations

- **`encrypt_batch()`** — encrypt multiple fields in a single call with per-table key amortization
- **`decrypt_batch()`** — decrypt multiple fields independently (partial failure safe)
- **Streaming encrypt/decrypt** — chunk-based processing for large payloads

### Type Safety

- **`Encrypted<T>`** — randomized encryption wrapper (Display shows `[ENCRYPTED]`)
- **`Searchable`** — ciphertext + blind index pair
- **`Deterministic`** — deterministic encryption wrapper (implements `Hash`)
- **`#[derive(VaultEncrypt)]`** — compile-time field encryption with validation

### ORM Integration

- **SQLx** — `Encrypted<String>` implements `sqlx::Type<Postgres>` (crate: `enkastela-sqlx`)
- **Diesel** — custom SQL types for encrypted columns (crate: `enkastela-diesel`)
- **SeaORM** — value type integration (crate: `enkastela-sea`)

### Security Guarantees

- **Zero key leakage** — `SecretKey` has no `Clone`, `Debug`, `Display`, or `Serialize`
- **Automatic zeroization** — all key material scrubbed on drop via `zeroize`
- **Sanitized errors** — no distinction between "wrong key" and "tampered ciphertext"
- **AAD binding** — ciphertext is bound to table:column via length-prefixed encoding
- **TLS enforcement** — `require_tls = true` by default
- **SSRF prevention** — all KMS provider URLs and resource names are validated
- **OWASP-aware coding practices** — no `.expect()` on crypto paths, proper error propagation, input validation, mutex poison handling

## Quick Start

```rust
use enkastela::Vault;

let vault = Vault::builder()
    .master_key_from_env("ENKASTELA_MASTER_KEY")
    .allow_insecure_connection()  // only for local dev
    .build()
    .await?;

// Encrypt
let ciphertext = vault.encrypt_field("users", "email", b"alice@example.com").await?;
// -> "ek:1:v1:dGhpcyBpcyBub3..."

// Decrypt
let plaintext = vault.decrypt_field("users", "email", &ciphertext).await?;
assert_eq!(&*plaintext, b"alice@example.com");

// Searchable encryption
let index = vault.compute_blind_index("users", "email", b"alice@example.com")?;
// Same input always produces the same 32-byte index
```

## Cloud KMS

```rust
// AWS KMS (feature: kms-aws)
let vault = Vault::builder()
    .master_key_from_aws_kms("arn:aws:kms:ap-southeast-1:123:key/abc-def")
    .build().await?;

// GCP Cloud KMS (feature: kms-gcp)
let vault = Vault::builder()
    .master_key_from_gcp_kms("projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key")
    .build().await?;

// Azure Key Vault (feature: kms-azure)
let vault = Vault::builder()
    .master_key_from_azure_kv("https://my-vault.vault.azure.net/keys/my-key/version")
    .build().await?;

// HashiCorp Vault (feature: kms-hashicorp)
let vault = Vault::builder()
    .master_key_from_hashicorp_vault("https://vault.internal:8200", "transit/keys/enkastela")
    .build().await?;
```

## Deterministic Encryption

For fields that need unique constraints or exact-match lookups:

```rust
let ct = vault.encrypt_field_deterministic("users", "ssn", b"123-45-6789").await?;
let pt = vault.decrypt_field_deterministic("users", "ssn", &ct).await?;

// Same plaintext + key = same ciphertext (enables DB unique constraints)
```

## Access Control

```rust
use enkastela::access::policy::{AccessPolicy, Permission};
use enkastela::access::context::AccessContext;

let mut policy = AccessPolicy::new();
policy.grant("support", "users", "name", Permission::Decrypt);
policy.grant("admin", "users", "ssn", Permission::Full);
policy.grant_admin("superadmin");

let vault = Vault::builder()
    .master_key_from_env("ENKASTELA_MASTER_KEY")
    .access_policy(policy)
    .build().await?;

let ctx = AccessContext::new("support").with_caller("user-123");
let pt = vault.decrypt_field_with_context("users", "name", &ct, &ctx).await?;
// -> Ok(plaintext)

let result = vault.decrypt_field_with_context("users", "ssn", &ct, &ctx).await;
// -> Err(AccessDenied)
```

## With Derive Macros

```rust
use enkastela_derive::VaultEncrypt;
use enkastela::VaultEncryptable;

#[derive(VaultEncrypt)]
#[vault(table = "users")]
struct User {
    id: i64,

    #[encrypt]
    full_name: String,

    #[encrypt(searchable)]
    email: String,

    #[encrypt(deterministic)]
    national_id: String,
}

// Generated: User::table_name() -> "users"
// Generated: User::encrypted_fields() -> [full_name(Randomized), email(Searchable), national_id(Deterministic)]
```

## Wire Format

```
ek:{format_version}:v{dek_version}:{base64url(nonce || ciphertext || tag)}
```

- `ek:` -- 3-byte prefix
- Format version and DEK version are independent (forward compatibility)
- Base64URL encoding (PostgreSQL-safe, no `+`, `/`, or padding)
- Binary layout: `nonce(12B) || ciphertext(variable) || tag(16B)`

## Feature Flags

```toml
[dependencies]
enkastela = { version = "0.1", features = ["audit"] }  # default
```

| Feature | Description | Dependencies |
|---------|-------------|-------------|
| `audit` | Audit trail with HMAC hash chain (default) | - |
| `streaming` | Chunked encryption for large payloads | - |
| `ore` | Order-Revealing Encryption for range queries | - |
| `bloom` | Bloom filter blind indexes for partial search | - |
| `fips` | FIPS-140 crypto backend (via aws-lc-rs) | `aws-lc-rs` |
| `kms-aws` | AWS KMS envelope encryption | `aws-sdk-kms`, `aws-config` |
| `kms-gcp` | GCP Cloud KMS key wrapping | `gcp-auth`, `reqwest` |
| `kms-azure` | Azure Key Vault key wrapping | `azure_security_keyvault_keys`, `azure_identity` |
| `kms-hashicorp` | HashiCorp Vault Transit engine | `reqwest` |
| `firewall` | SQL query analysis and firewall | `sqlparser` |
| `intrusion` | Poison record intrusion detection | - |
| `access-control` | Role-based field access control | - |
| `compliance` | SOC2/GDPR/HIPAA control mapping helpers | - |
| `metrics-prometheus` | Prometheus metrics exporter | `prometheus` |
| `otel` | OpenTelemetry metrics integration | `opentelemetry` |

## Security Model

| Threat | Protection | Mechanism |
|--------|-----------|-----------|
| Database breach | Encrypted fields unreadable | AES-256-GCM |
| DBA reads PII | App-side encryption | Field-level encryption |
| Ciphertext relocation | Detected and rejected | AAD binds to table:column |
| Single DEK compromise | Only one table affected | Per-table DEKs |
| Ciphertext tampering | Detected | GCM authentication tag |
| Memory disclosure | Keys zeroed on drop | `zeroize` crate |
| GDPR right to erasure | Instant data erasure | Crypto-shredding |
| Audit tampering | Detected | HMAC hash chain |
| Timing side-channel | Mitigated | Constant-time comparison |
| Tenant data isolation | Cryptographic separation | Random per-tenant keys |
| Unauthorized access | Role-based access control | Field-level policies |
| SQL bypass attack | Detected and blocked | SQL Firewall |
| Data exfiltration | Detected via honeypots | Poison record alerts |

## Architecture

```
enkastela/
├── crypto/          # AES-GCM, AES-SIV, HKDF, KWP, HMAC, ORE, streaming, FIPS backend
├── keyring/         # Key derivation, caching, wrapping, AWS/GCP/Azure/HashiCorp providers
├── storage/         # Wire format codec, repository trait, SQL migrations, connection pool
├── audit/           # Async batched logger, HMAC hash chain integrity
├── blind/           # Blind index, Unicode normalization, Bloom filter
├── tenant/          # Per-tenant key isolation and crypto-shredding
├── rotation/        # Key rotation engine, re-encryption pipeline
├── gdpr/            # Erasure receipts, data export
├── access/          # Role-based field access control policies
├── firewall/        # SQL query analysis and policy enforcement
├── intrusion/       # Poison records and anomaly detection
├── compliance/      # SOC2, GDPR, HIPAA compliance reports
├── observability/   # Metrics trait, Prometheus, OpenTelemetry, health checks
├── types/           # Encrypted<T>, Searchable, Deterministic, encrypted JSONB
├── validation/      # Input validation, AAD construction
├── vault.rs         # Main Vault API
├── config.rs        # Configuration
└── error.rs         # Sanitized error types
```

## CLI

```bash
# Generate a master key
enkastela keygen

# Encrypt a value
enkastela encrypt --key $KEY --table users --column email --value "alice@example.com"

# Decrypt a value
enkastela decrypt --key $KEY --table users --column email --value "ek:1:v1:..."

# Check if a value is encrypted
enkastela check --value "ek:1:v1:..."
```

## MSRV

The minimum supported Rust version is **1.88**.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please read [SECURITY.md](SECURITY.md) before reporting security issues.
