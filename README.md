# SurfaceLint

**Lint your public security surface from one local binary.**

SurfaceLint is a local-first, open-source security posture assessment CLI for small businesses, startups, nonprofits, developers, and administrators who want a fast view of common public-facing security controls.

It runs on the user's computer, requires no SurfaceLint account or hosted service, and does not upload scan results.

> **Project status:** v0.1 development preview. The scoring model and checks will evolve before v1.0.

## What v0.1 checks

- Validated HTTPS/TLS connectivity
- Certificate expiration
- TLS 1.0 and 1.1 exposure
- TLS 1.2 / 1.3 support
- HTTP to HTTPS redirection
- HSTS
- Content-Security-Policy
- X-Content-Type-Options
- Clickjacking protection
- Referrer-Policy
- Permissions-Policy
- SPF
- DMARC policy

## Quick start

Requires Go 1.27+ when building from source.

```bash
git clone https://github.com/cnorton-dev/surfacelint.git
cd surfacelint
go run ./cmd/surfacelint scan example.com
```

Or build a local binary:

```bash
go build -o surfacelint ./cmd/surfacelint
./surfacelint scan example.com
```

Windows PowerShell:

```powershell
go build -o surfacelint.exe ./cmd/surfacelint
.\surfacelint.exe scan example.com
```

By default SurfaceLint writes an HTML report to `./reports/`.

```bash
surfacelint scan example.com --report ./example-security-report.html
surfacelint scan example.com --no-report
```

## Example output

```text
SurfaceLint Security Assessment
Target: example.com

TLS
---
[PASS] Validated TLS connection         Negotiated TLS 1.3 ...
[PASS] Legacy TLS protocols disabled    TLS 1.0 and TLS 1.1 were not accepted.

HTTP
----
[PASS] HTTP redirects to HTTPS          HTTP 301 redirects to https://example.com/.
[WARN] Content Security Policy          Content-Security-Policy header was not present.

Email/DNS
---------
[PASS] SPF record                       SPF: v=spf1 ...
[WARN] DMARC policy                     DMARC is present but uses p=none.

Security Score: 84/100
```

## Philosophy

SurfaceLint is intentionally local-first:

- no account required
- no hosted SurfaceLint backend
- no telemetry in v0.1
- no scan-result uploads
- no database server required
- reports are generated locally

The project focuses on understandable findings and actionable remediation rather than producing a large volume of scanner output.

## Safety and scope

SurfaceLint v0.1 uses lightweight public HTTPS, TLS, HTTP, and DNS checks. It does not exploit vulnerabilities, brute-force services, bypass authentication, or perform intrusive testing.

Only scan systems you own or are authorized to assess.

## Roadmap

### v0.2
- SQLite scan history
- `surfacelint history <domain>`

### v0.3
- `surfacelint compare`
- posture-change reporting

### v0.4
- cookie security checks
- `security.txt`
- CAA
- DNSSEC detection
- redirect-chain analysis

### v0.5
- JSON output
- CI-friendly exit codes
- configurable policies

### v1.0
- stable scoring model
- signed cross-platform releases
- polished documentation

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report vulnerabilities according to [SECURITY.md](SECURITY.md).

## License

MIT License. See [LICENSE](LICENSE).

## Architecture and design

- [Architecture](docs/ARCHITECTURE.md)
- [Scoring model](docs/SCORING.md)
- [Roadmap](docs/ROADMAP.md)
