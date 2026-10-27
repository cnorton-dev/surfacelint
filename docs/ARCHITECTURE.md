# SurfaceLint Architecture

SurfaceLint is local-first, without hosted infrastructure, user accounts, telemetry or a database server.

```text
CLI (scan/history/compare)
  |       |       |
  |       |       +----> History.Store.List ----> Drift.Compare ----> JSON/text
  |       +------------> History.Store.List ----> Recent scores
  v
Target normalization
  |
Concurrent Scan coordinator
  |---- TLS handshake / certificate / protocol probes
  |---- HTTP / header inspection
  `---- DNS TXT / email authentication
  |
Findings (stable IDs, status, severity, evidence, recommendation)
  |
Deterministic score
  |---- terminal / JSON / escaped local HTML
  `---- optional History.Store.Append (per-domain JSONL files)
```

`internal/checks` contains isolated network-facing checks, `internal/scanner` orchestrates them and applies the scoring model, `internal/model` contains cross-package types, `internal/report` handles output, `internal/history` stores results locally, and `internal/drift` classifies findings by ID across two saved snapshots.

The implementation uses only the standard library. Scan history uses append-only JSONL, making records inspectable without specialized tooling and simplifying cross-platform builds. Each saved snapshot is independent; no database migration step is required yet.

## Tradeoffs and security boundaries

- The checks are low impact but they make real outbound network requests. Use only against authorized targets.
- Scan history is deliberately opt-in to avoid retaining security data unexpectedly.
- Reports use `html/template` escaping. JSON output is suitable for machine processing.
- An HTML report is the default for text scans, but JSON scans do not write it unless a path is explicitly requested; stdout therefore contains only JSON.
- `--fail-on` is a user-selected status policy, not a claim that a score automatically means a system is secure.
- Version 0.2 does not yet defend against DNS rebinding/private-address redirection and should not accept untrusted target submissions in a privileged or private-network deployment.
