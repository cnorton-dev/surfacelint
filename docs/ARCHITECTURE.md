# SurfaceLint Architecture

SurfaceLint is intentionally local-first. It has no hosted control plane, account system, telemetry service, or required database server.

## Data flow

```text
User command
    |
    v
Target normalization
    |
    v
Concurrent scan coordinator
    |----------- TLS checks
    |----------- HTTP/header checks
    `----------- DNS/email-authentication checks
                    |
                    v
              Findings model
                    |
                    v
               Score engine
                 /     \
                v       v
        Terminal output HTML report
```

## Packages

- `cmd/surfacelint`: CLI entry point and command-line options.
- `internal/target`: target normalization and input validation.
- `internal/checks`: network-facing posture checks.
- `internal/model`: common result and finding types.
- `internal/scanner`: concurrent orchestration and scoring.
- `internal/report`: terminal and self-contained HTML reports.

## Design constraints

### Local-first

Scan results stay on the local machine. SurfaceLint does not require a SurfaceLint-hosted API.

### Minimal dependencies

v0.1 uses only the Go standard library. This reduces supply-chain surface area and makes cross-platform static builds straightforward.

### Non-invasive checks

v0.1 performs ordinary TLS handshakes, HTTP requests, and DNS lookups. It does not brute-force services, exploit vulnerabilities, bypass authentication, or modify the target.

### Explainable findings

Every actionable finding carries evidence, severity, and remediation text. The report should tell a user what was observed and what to do next.

### Deterministic scoring

The score is calculated only from emitted findings. Identical findings produce the same score regardless of platform.

## Future architecture

v0.2 will add SQLite behind a storage interface for local scan history. The network scanner will remain usable without a persistent database so one-shot scans stay simple.
