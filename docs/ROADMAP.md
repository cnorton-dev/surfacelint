# Roadmap

## v0.1 - Public posture baseline

- TLS and certificate checks
- HTTP-to-HTTPS redirect behavior
- common browser security headers
- SPF and DMARC
- deterministic scoring
- terminal output
- local self-contained HTML report
- cross-platform release automation

## v0.2 - Local history

- SQLite storage
- `surfacelint history <domain>`
- retention controls
- schema migrations

## v0.3 - Drift

- `surfacelint compare`
- fixed/new/unchanged findings
- score trend

## v0.4 - Expanded public posture

- cookie attributes
- `security.txt`
- CAA
- DNSSEC detection
- redirect-chain analysis

## v0.5 - Automation

- JSON output
- stable exit codes for CI
- configurable policy files
- finding suppression with justification

## v1.0 - Stable CLI

- versioned scoring contract
- signed release artifacts
- stable JSON schema
- complete CLI reference
