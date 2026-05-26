# Contributing

Thanks for considering a contribution. This module signs Ethereum transactions
with AWS KMS-stored secp256k1 keys, so changes are held to a high correctness
and security bar.

## Local development

Required: Go 1.24 or newer (CI runs the matrix 1.24 → 1.26).

```bash
# Build everything
go build ./...

# Unit tests, race detector on
go test -race ./...

# Coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Lint (matches CI)
golangci-lint run ./...

# Vulnerability scan
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

The container-based test suite uses Docker (via testcontainers-go) to run
[`nsmithuk/local-kms`](https://github.com/nsmithuk/local-kms) so tests do not
need real AWS credentials. Make sure Docker is available locally.

## Pull requests

- Keep changes focused. Crypto and signing code is reviewed line-by-line;
  large drive-by refactors slow that down.
- Add tests for any new code path. Reach for fuzz tests when the input
  could be attacker-controlled (signature parsing, public-key parsing,
  R/S length normalisation).
- Run `go mod tidy` before submitting — CI fails if `go.mod`/`go.sum`
  aren't tidy.
- Update `README.md` if behavior or configuration knobs change.
- Mark behavior-affecting changes clearly in the PR description.

## Backward compatibility

This module has production consumers signing real Ethereum transactions.
Treat the public API as stable:

- Do not change the signatures of `NewAwsKmsTransactorWithChainID[Ctx]`,
  `GetPubKey[Ctx]`, or exported helpers without a major version bump.
- New configuration is added as additional functions (e.g. a future
  `SetPubKeyCacheTTL`) rather than by changing existing constructors.
- The default behaviour of the public-key cache must remain unchanged so
  existing applications continue to work after an upgrade.

## Releases

Tags follow Go's [semantic import versioning](https://go.dev/ref/mod#versions).
New tags use the canonical `vX.Y.Z` format.

Signed annotated tags are preferred (`git tag -as vX.Y.Z`).

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.
