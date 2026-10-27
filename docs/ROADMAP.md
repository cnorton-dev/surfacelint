# Roadmap

## v0.1 - Public posture baseline (initial release)

- TLS/certificate, common HTTP security headers, SPF/DMARC
- Concurrent scanner, deterministic score, HTML/terminal reports
- Cross-platform CI and release packaging

## v0.2 - Automation and comparisons (this branch)

- Opt-in local JSONL history (dependency-free alternative to proposed SQLite)
- `surfacelint history` and `surfacelint compare`
- JSON output for scan and comparison
- CI exit threshold (`--fail-on`)
- Unit tests for storage, comparison, and serialization

## v0.3 - Expanded coverage

- `security.txt` validation
- Certificate Authority Authorization (CAA)
- Cookie `Secure`, `HttpOnly`, `SameSite` audits
- Redirect-chain analysis, DNSSEC and MX inspection

## v0.4 - Hardening

- DNS pinning / private-address egress restrictions for untrusted target inputs
- Explicit policy files and justified suppressions
- Stable JSON schema versioning
- Better handling of temporarily unavailable endpoints

## v1.0 - Stable CLI

- Versioned scoring contract and compatibility guarantees
- Signed release artifacts and reproducible builds
- Complete CLI reference and migration docs
