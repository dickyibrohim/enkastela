# Security Policy

## Disclaimer

This software is provided **"AS IS"**, without warranty of any kind. The author(s) assume no responsibility or liability for any damage, data loss, or security incidents arising from the use of this software. Use at your own risk.

## Reporting a Vulnerability

If you discover a security vulnerability, you may report it via:

1. **GitHub Security Advisories** (preferred) — use the "Report a vulnerability" button on the repository
2. **GitHub Issues** — if you are comfortable disclosing publicly

There is **no guarantee** of response time or patch availability. This is a community-driven open source project maintained on a best-effort basis.

## Disclosure Policy

- Reporters are free to disclose vulnerabilities at any time through any channel
- The maintainer(s) will address reports when available, but make no commitments on timeline
- Contributions (pull requests with fixes) are always welcome

## Cryptographic Audit Status

Enkastela has **not undergone a professional security audit**. The library uses audited RustCrypto crates for all cryptographic primitives, but the integration and usage patterns have not been independently reviewed.

**If you use this library in production, you do so at your own risk.**

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | Best-effort only |

## Security Design

See [docs/threat-model.md](docs/threat-model.md) for documentation on what Enkastela is designed to protect against and its known limitations.
