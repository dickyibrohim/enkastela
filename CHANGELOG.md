# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-03-29

### Fixed

#### Security
- **Key separation violation**: audit HMAC key and tenant master key were
  using raw master key bytes instead of HKDF-derived sub-keys. Now both are
  independently derived via `HKDF(master_key, salt, domain_info)` before the
  master key is consumed by the keyring manager. The existing
  `KeyringManager::derive_audit_key()` method (which was never wired in) is
  now used correctly.
- **Missing audit trail for deterministic operations**: `encrypt_field_deterministic`
  and `decrypt_field_deterministic` did not emit audit events, creating a blind
  spot for compliance (SOC2/HIPAA). Both methods now log `AuditAction::Encrypt`
  and `AuditAction::Decrypt` respectively.

#### Bug Fixes
- **`InMemoryKeyRepository::store_tenant_key`** returned `TenantAlreadyErased`
  when an active tenant key already existed — the opposite of the actual state.
  Now returns `Ok(())` silently, matching the PostgreSQL backend's
  `ON CONFLICT DO NOTHING` semantics.

### Changed
- `TenantKeyManager::get_tenant_key` no longer uses a redundant drop-relock
  pattern. The wrapped key bytes are cloned while the lock is held, then the
  lock is released before calling `unwrap_key`. Single lock acquisition, no
  TOCTOU window.
- `Vault::decrypt_stream` now delegates to the new `decrypt_stream_with_version`
  method internally (no behavior change for callers).

### Added
- `Vault::decrypt_stream_with_version(table, column, ciphertext, version)` —
  allows decrypting stream-encrypted data with an explicit DEK version.
- Defensive guard in `encrypt_stream` that returns `PayloadTooLarge` if the
  chunk count would overflow `u32` (unreachable with default config, but
  prevents silent truncation for extreme edge cases).
- 20 new integration tests (`bugfix_verification.rs`) covering all fixes with
  end-to-end production simulation scenarios.

## [0.1.0] - 2026-03-18

### Added

#### Cryptographic Core
- AES-256-GCM authenticated encryption with per-field CSPRNG nonces
- AES-256-SIV deterministic encryption for unique constraints and exact-match lookups
- HKDF-SHA256 key derivation with domain separation (`enkastela:{purpose}:{scope}:{version}`)
- AES-256 Key Wrapping (RFC 3394) for secure DEK storage
- Constant-time comparison via `subtle` crate for all tag/hash verification
- 96-bit CSPRNG nonce generation via `OsRng`
- Streaming chunked AES-256-GCM encryption for large payloads (>16 MiB)
- Order-Revealing Encryption (ORE) for range queries without decryption (feature: `ore`)
- FIPS-140 validated crypto backend via `aws-lc-rs` (feature: `fips`)
- Pluggable `CryptoBackend` trait with RustCrypto (default) and FIPS implementations

#### Key Management
- Per-table DEK derivation with independent key versions
- LRU + TTL bounded key cache using `DashMap` for concurrent access
- Key lifecycle management (`Active` -> `Rotating` -> `Retired` -> `Destroyed`)
- Physical key material zeroing on destruction
- `MasterKeyProvider` trait for pluggable KMS integration
- `EnvKeyProvider` for environment variable-based master key loading
- `StaticKeyProvider` for testing
- Multi-master key hierarchy with provider selection and migration support

#### Cloud KMS Integration
- AWS KMS provider with envelope encryption via `GenerateDataKey`/`Decrypt` (feature: `kms-aws`)
- GCP Cloud KMS provider with key wrapping and SSRF prevention (feature: `kms-gcp`)
- Azure Key Vault provider with wrap/unwrap operations (feature: `kms-azure`)
- HashiCorp Vault Transit engine provider with URL validation (feature: `kms-hashicorp`)

#### Wire Format
- Wire format v1: `ek:{format_version}:v{dek_version}:{base64url(nonce || ciphertext || tag)}`
- Format version independent from DEK version for forward compatibility
- Base64URL encoding (PostgreSQL-safe, no `+`, `/`, or padding)

#### Vault API
- `Vault::encrypt_field()` -- randomized field encryption
- `Vault::decrypt_field()` -- field decryption with AAD verification
- `Vault::encrypt_field_deterministic()` -- deterministic encryption for unique constraints
- `Vault::decrypt_field_deterministic()` -- deterministic decryption
- `Vault::encrypt_batch()` / `Vault::decrypt_batch()` -- batch operations
- `Vault::encrypt_stream()` / `Vault::decrypt_stream()` -- streaming encryption
- `Vault::encrypt_field_with_context()` / `Vault::decrypt_field_with_context()` -- access-controlled operations
- `Vault::compute_blind_index()` -- HMAC-SHA256 blind index for equality search
- `Vault::compute_text_blind_index()` -- blind index with Unicode NFC normalization
- `VaultBuilder` with fluent configuration API
- TLS enforcement by default (`require_tls = true`)

#### Searchable Encryption
- HMAC-SHA256 blind indexes for equality search on encrypted data
- Unicode NFC normalization for consistent blind index computation
- Compound blind indexes for multi-field search
- Truncatable indexes with configurable output size (8-32 bytes)
- Bloom filter blind indexes for partial/prefix search via n-gram hashing (feature: `bloom`)

#### Encrypted JSONB
- Selective field encryption within JSON objects via JSON Pointer (RFC 6901)
- Support for nested paths and array elements
- Independent encrypt/decrypt of individual JSON fields

#### Security Features
- SQL Firewall -- detect queries that bypass encryption using `sqlparser` (feature: `firewall`)
- Intrusion detection -- poison/honeypot records with alert triggers (feature: `intrusion`)
- Field-level access control -- role-based encrypt/decrypt permissions (feature: `access-control`)
- Compliance reporting -- SOC2, GDPR, HIPAA control mapping reports (feature: `compliance`)

#### Multi-Tenant Isolation
- Random per-tenant key generation (not derived from master key)
- Tenant key wrapping with master key for storage
- Crypto-shredding: destroy tenant key to make all data permanently unrecoverable

#### GDPR Compliance
- `erase_tenant()` -- crypto-shredding with physical key zeroing
- `ErasureReceipt` with SHA-256 pre-destruction proof
- Constant-time receipt verification
- `DataExport` -- JSON-serializable export for GDPR Article 20 data portability

#### Audit Trail
- Async batched audit logger with bounded `mpsc` channel
- HMAC-SHA256 hash chain for tamper-evident integrity
- Configurable overflow policy: block-with-timeout or drop-and-count
- `AuditSink` trait for pluggable storage backends
- `InMemoryAuditSink` for testing
- Graceful flush on Drop to prevent event loss

#### Key Rotation
- `RotationEngine` orchestrator with progress tracking
- Lazy rotation strategy (re-encrypt on next read)
- Eager rotation strategy (background batch processing)
- Re-encryption pipeline with cursor-based pagination and crash recovery
- Resumable rotation with checkpoint-based progress

#### Observability
- `MetricsRecorder` trait for pluggable metrics (Prometheus, StatsD, etc.)
- Prometheus integration with 12+ pre-built metrics (feature: `metrics-prometheus`)
- OpenTelemetry integration with vendor-agnostic telemetry (feature: `otel`)
- `InMemoryMetrics` for testing with atomic counters
- Health check API with subsystem status (cache, audit logger)
- `NoOpMetrics` for zero-overhead production default

#### Type System
- `Encrypted<T>` -- randomized encryption wrapper (`Display` shows `[ENCRYPTED]`)
- `Searchable` -- ciphertext + blind index pair
- `Deterministic` -- deterministic encryption wrapper (implements `Hash`)
- `VaultEncryptable` trait for struct-level encryption
- `#[derive(VaultEncrypt)]` proc macro with compile-time validation

#### ORM Integration
- `enkastela-sqlx` crate: `Encrypted<String>` implements `sqlx::Type<Postgres>`
- `enkastela-diesel` crate: custom SQL types for encrypted columns
- `enkastela-sea` crate: SeaORM value type integration

#### Input Validation
- Length-prefixed AAD encoding to prevent delimiter collision attacks
- Maximum payload size enforcement (16 MiB)
- Key version range validation
- KMS URL and resource name validation (SSRF prevention)

#### Security
- `SecretKey` with no `Clone`, `Debug`, `Display`, or `Serialize`
- Automatic zeroization of all key material on drop via `zeroize`
- Sanitized error messages -- no distinction between "wrong key" and "tampered ciphertext"
- `Zeroizing<Vec<u8>>` for all intermediate plaintext buffers
- Intermediate key material wrapped in `Zeroizing` during provider loading
- OWASP Top 10 compliant error handling (no `.expect()` on crypto paths)
- Mutex poison recovery in audit logger
- Proper TLS URL parameter parsing

#### CLI
- `enkastela keygen` -- generate 32-byte master key (base64-encoded)
- `enkastela encrypt` -- encrypt a value from the command line
- `enkastela decrypt` -- decrypt a value from the command line
- `enkastela check` -- verify if a value is in encrypted wire format

#### Infrastructure
- 7-crate workspace: `enkastela`, `enkastela-derive`, `enkastela-cli`, `enkastela-test`, `enkastela-sqlx`, `enkastela-diesel`, `enkastela-sea`
- CI pipeline: check, test, clippy, fmt, doc, deny, MSRV (1.88), coverage
- Security audit workflow (weekly `cargo audit`)
- Benchmark pipeline with regression detection
- Dependabot configuration for automated dependency updates
- Branch protection on `main` (no force push, no deletion)
- Comprehensive `.gitignore` for security-sensitive files
- 427 tests (386 unit + 25 integration + 14 property-based + fuzz targets)
- 5 benchmark suites (crypto primitives, field encryption, key cache, blind index, concurrent)
- 3 runnable examples (basic encryption, searchable encryption, key derivation)
- Threat model documentation
- Security policy with vulnerability reporting guidelines
