# Threat Model

## What Enkastela Protects Against

### Database Breach (Data at Rest)

**Threat:** An attacker gains read access to the PostgreSQL database through SQL injection, stolen credentials, or physical disk access.

**Protection:** All sensitive fields are encrypted with AES-256-GCM. The attacker sees only ciphertext (`ek:1:v1:...`). Without the master key (which is never stored in the database), the data is computationally infeasible to decrypt.

### Malicious or Compromised DBA

**Threat:** A database administrator with full access reads sensitive user data.

**Protection:** Encryption happens at the application layer before data reaches the database. The DBA can see table structures and ciphertext, but cannot decrypt field values.

### Ciphertext Relocation / Substitution

**Threat:** An attacker copies an encrypted value from one column/table and places it in another.

**Protection:** Each encryption operation binds the ciphertext to its table and column via Additional Authenticated Data (AAD). Decrypting a ciphertext with different AAD fails authentication.

### Ciphertext Tampering

**Threat:** An attacker modifies encrypted data in the database.

**Protection:** AES-256-GCM produces a 128-bit authentication tag. Any modification to the ciphertext, nonce, or AAD causes decryption to fail.

### Single Key Compromise

**Threat:** A data encryption key (DEK) for one table is compromised.

**Protection:** Each table derives its own DEK via HKDF with domain separation (`enkastela:dek:{table}:{version}`). Compromising one table's DEK does not affect other tables.

### Memory Disclosure

**Threat:** Key material remains in memory after use, accessible through memory dumps or cold boot attacks.

**Protection:** All key types implement `ZeroizeOnDrop`. Key material is overwritten with zeros when dropped. Intermediate plaintext buffers use `Zeroizing<Vec<u8>>`.

### GDPR Right to Erasure

**Threat:** Regulatory requirement to permanently delete all data belonging to a specific user or tenant.

**Protection:** Crypto-shredding — destroying a tenant's encryption key makes all their encrypted data permanently unrecoverable, without needing to locate and delete individual records.

### Audit Log Tampering

**Threat:** An attacker deletes or modifies audit log entries to cover their tracks.

**Protection:** Each audit event includes an HMAC-SHA256 hash that chains to the previous event. Tampering, deletion, or reordering of events breaks the chain and is detectable via verification.

### Timing Side-Channel

**Threat:** An attacker measures response times to distinguish between "wrong key" and "tampered ciphertext" errors.

**Protection:** Authentication tag comparison uses constant-time operations via the `subtle` crate. Error messages do not distinguish between failure modes.

## What Enkastela Does NOT Protect Against

### Compromised Application Server

If the attacker has access to the running application process, they can read the master key from memory and decrypt data. Enkastela protects the database, not the application runtime.

### Traffic Analysis

An attacker observing database queries can see which rows are accessed and when. Enkastela does not hide access patterns.

### Equality Leakage (Blind Indexes & SIV)

Blind indexes and deterministic encryption reveal when two values are identical. An attacker with database access can determine that two users share the same email or national ID without knowing the actual value.

### Frequency Analysis on Blind Indexes

If the distribution of a field is known (e.g., country codes), an attacker may correlate blind index frequencies with the known distribution.

### Partial Match / Range Queries

Encrypted fields cannot support `LIKE`, `>`, `<`, or `ORDER BY` operations at the database level. Only exact-match lookups via blind indexes are supported.

### Key Management Infrastructure

Enkastela does not provide a KMS. The master key must be securely provisioned via environment variables or a custom `MasterKeyProvider` implementation connected to a proper KMS (AWS KMS, GCP KMS, HashiCorp Vault).

### Backup-Mediated Recovery After Crypto-Shredding

Database backups taken before crypto-shredding still contain the wrapped DEK. If both the backup and the master key are available, data can be recovered. Organizations should align backup retention policies with erasure requirements.

## Cryptographic Primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Authenticated encryption | AES-256-GCM | NIST SP 800-38D |
| Deterministic encryption | AES-256-SIV | RFC 5297 |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Key wrapping | AES-256-KWP | RFC 3394 |
| Blind index | HMAC-SHA256 | RFC 2104 |
| Constant-time comparison | `subtle` crate | — |
| Memory zeroization | `zeroize` crate | — |

All cryptographic operations delegate to the RustCrypto ecosystem. Enkastela contains zero `unsafe` blocks and zero custom cryptographic implementations.

## Security Invariants

1. No key material appears in logs, error messages, or debug output
2. All key material is zeroized on drop
3. Nonces are never reused (96-bit CSPRNG from `OsRng`)
4. AAD binds ciphertext to its table and column context
5. Destroyed keys have their material physically zeroed (not just flagged)
6. Error messages do not distinguish between "wrong key" and "tampered data"
7. TLS is required by default for database connections
