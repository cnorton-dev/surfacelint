# SurfaceLint

**Lint your public security surface from one local binary.**

SurfaceLint is a local-first Go CLI that checks public HTTPS/TLS, HTTP security headers, and email DNS authentication. It summarizes findings in the terminal and a self-contained HTML report, with opt-in local history for trend analysis. There is no account, hosted backend, or telemetry.

> **Status:** v0.2 development preview, not a penetration test or compliance audit. Checks and scoring may change before v1.0.

## Checks

- Validated HTTPS/TLS connection and certificate expiration
- TLS 1.0/1.1 exposure and TLS 1.2/1.3 support
- HTTP-to-HTTPS redirection
- HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy
- SPF and DMARC policy

## Install from source

Requires Go 1.27+ (per `go.mod`).

```bash
git clone https://github.com/cnorton-dev/surfacelint.git
cd surfacelint
go build -o surfacelint ./cmd/surfacelint
./surfacelint version
```

## Usage

```bash
# Default: text output and local HTML report under reports/
./surfacelint scan example.com

# Opt-in to local history, compare scans over time
./surfacelint scan --save example.com
./surfacelint scan --save example.com
./surfacelint history example.com
./surfacelint compare example.com

# Machine-readable JSON, with no HTML report by default
./surfacelint scan --format json --no-report example.com
./surfacelint compare --format json example.com

# CI-friendly exit status
./surfacelint scan --format json --fail-on fail example.com > scan.json

# Custom report, scan timeout, or history directory
./surfacelint scan --timeout 20s --report ./scan.html --save --data-dir ./local-history example.com
```

**Exit codes:** `0` for a completed scan below the specified threshold; `1` for a runtime/scan-command error; `2` for missing or unknown top-level commands; `3` when `--fail-on warn` or `--fail-on fail` finds a matching status. Without `--fail-on`, security findings do not cause a nonzero exit status.

**Important:** Scan flags must appear before the domain, for example `scan --save example.com`.

### Opt-in local history

`--save` appends JSON Lines records to a per-hostname file under your OS user config directory (`surfacelint/history/`) or an explicit `--data-dir`. The directory and files use restrictive Unix permissions where supported. `history` shows recent scores, while `compare` compares the two most recent scans by finding ID, reporting new, removed, improved, regressed, and changed findings.

History uses standard-library JSONL rather than SQLite so the CLI can remain a single dependency-free Go binary. In case the local history needs migration or SQLite later, the persistence implementation is isolated under `internal/history`.

### CI automation

This Bash example fails the job only when a finding has `fail` status and preserves the JSON evidence as an artifact:

```bash
set +e
./surfacelint scan --format json --no-report --fail-on fail example.com > scan.json
code=$?
set -e
if [ "$code" -eq 3 ]; then
  echo 'Security findings exceeded policy threshold' >&2
  exit 3
fi
exit "$code"
```

## Security and privacy

- Only scan hosts you own or are authorized to assess.
- SurfaceLint makes ordinary public DNS, HTTP, and TLS requests. It never attempts exploitation or authentication bypass.
- Results are not uploaded by SurfaceLint. `--save` is optional.
- Security findings require human review: missing headers or a failed connection do not prove exploitability.
- Do not pass attacker-controlled URLs or domains to a scan agent with access to private networks. This preview does not implement DNS-rebinding-resistant egress filtering.

## Project layout

| Path | Responsibility |
|---|---|
| `cmd/surfacelint` | CLI commands and threshold policy |
| `internal/checks` | Public TLS, HTTP, and DNS observations |
| `internal/scanner` | Parallel scan coordination and scoring |
| `internal/history` | Local append-only scan history |
| `internal/drift` | Deterministic finding comparisons |
| `internal/report` | Terminal, JSON and HTML output |
| `internal/model` | Shared typed result model |
| `internal/target` | Hostname normalization |

## Quality and releases

```bash
go test ./...
go vet ./...
go build ./cmd/surfacelint
```

CI covers Linux, macOS, and Windows; release automation packages binaries on git tags. The integration test is disabled by default and can be enabled via `SURFACELINT_INTEGRATION=1` on a network-connected machine.

See [architecture](docs/ARCHITECTURE.md), [scoring](docs/SCORING.md), [roadmap](docs/ROADMAP.md), [contributing](CONTRIBUTING.md), and [security](SECURITY.md).

MIT licensed.
