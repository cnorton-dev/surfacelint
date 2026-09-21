# Contributing to SurfaceLint

Thanks for helping improve SurfaceLint.

## Development setup

1. Install Go 1.27 or newer.
2. Fork and clone the repository.
3. Create a focused feature branch.
4. Run `go test ./...` before opening a pull request.
5. Run `gofmt` on changed Go files.

## Project principles

Contributions should preserve these goals:

- local-first operation
- no required hosted backend
- non-invasive security checks
- clear evidence and remediation
- minimal dependencies
- cross-platform behavior
- deterministic, testable scoring

## Pull requests

Keep changes focused. Include tests when behavior changes and update documentation when user-visible commands or checks change.

## New checks

A new security check should define:

- what is being tested
- why it matters
- pass/warn/fail criteria
- severity
- evidence shown to the user
- actionable remediation
- false-positive considerations
