<!-- Thanks for contributing! -->

## What

<!-- One- or two-sentence summary of the change. -->

## Why

<!-- The motivation. Link to any issues. -->

## How

<!-- Implementation notes for reviewers. Highlight anything subtle. -->

## Backward compatibility

<!-- Is this additive? Does it change defaults? Does it require a new major version? -->

## Test plan

- [ ] `go test -race ./...` passes
- [ ] `golangci-lint run ./...` passes
- [ ] `govulncheck ./...` passes
- [ ] New code paths have tests
- [ ] Public-API changes are documented in README.md

## Security

- [ ] This change does not affect signing, verification, or key handling
- [ ] OR: I have flagged the maintainer to review the security implications
