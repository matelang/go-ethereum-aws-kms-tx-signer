# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Overview

This is an AWS KMS (Key Management Service) transaction signer for go-ethereum.
It wraps an AWS KMS asymmetric secp256k1 key as a `*bind.TransactOpts` so that
generated `abigen` bindings — or any caller of the go-ethereum `bind` package —
can sign Ethereum transactions without ever materialising the private key in
process memory.

The same primitives are reused for EIP-712 typed-data signing.

## Development Commands

### Build
```bash
go build -v ./...
```

### Test
```bash
# All tests (will spin up nsmithuk/local-kms via testcontainers-go)
go test -v ./...

# Race detector + coverage
go test -race -covermode=atomic -coverprofile=coverage.out ./...

# Skip container-based tests (only the in-process unit tests)
go test -short ./...
```

### Lint and security
```bash
golangci-lint run ./...
govulncheck ./...
```

### Dependency Management
```bash
go mod tidy
```

## Architecture

### Core components

**`signer.go`**
- `NewAwsKmsTransactorWithChainID[Ctx]` — returns a `*bind.TransactOpts` whose
  `Signer` calls KMS for every transaction. Uses
  `types.LatestSignerForChainID`, which already handles legacy / EIP-2930 /
  EIP-1559 / EIP-4844 transactions, so there is no need for a separate "typed
  transaction" signer.
- `GetPubKey[Ctx]` — fetches the secp256k1 public key from KMS, parses the
  ASN.1 DER `SubjectPublicKeyInfo`, returns an `*ecdsa.PublicKey`. Results are
  cached in `keyCache`.
- `getSignatureFromKms` — calls `kms.Sign` with `MessageType=DIGEST` and
  `SigningAlgorithm=ECDSA_SHA_256`, then unmarshals the ASN.1 DER signature
  into raw `R` and `S` byte slices.
- `getEthereumSignature` — pads `R`/`S` to 32 bytes (via
  `adjustSignatureLength`), tries V=0 then V=1, and recovers the public key to
  pick the correct V byte. Returns the 65-byte `R||S||V` signature expected by
  `tx.WithSignature`.
- `adjustSignatureLength` — left-trims any ASN.1 leading 0x00 sign byte then
  left-pads back to exactly 32 bytes. The DER decoder can hand us back 31
  bytes (no padding byte was needed) or 33 (a sign-bit-clearing 0x00 was
  prepended); both must end up as 32.

**`pubkey_cache.go`**
- `sync.RWMutex`-guarded map `keyId → *ecdsa.PublicKey`.
- No TTL today — a KMS-side `kms:CancelKeyDeletion` or `UpdatePrimaryRegion`
  will not be reflected until the process restarts. Adding a TTL setter
  (mirroring the sister `jwt-go-aws-kms` repo) is a recognised follow-up.

**`typed_data_signer.go`** *(post-EIP-712 PR)*
- `AwsKmsTypedDataSigner` — implements EIP-712 typed-data signing. Reuses
  `getSignatureFromKms` and the same V-recovery + low-S normalisation from
  `signer.go`. Domain separator + struct hash are computed via
  `apitypes.TypedData` from `go-ethereum/signer/core/apitypes`.

## Important constraints

- **Low-S normalisation is mandatory.** Ethereum rejects high-S signatures
  (EIP-2). KMS returns whichever S half the underlying library produces, so
  the code must flip S to its low half before recovery.
- **DIGEST message type, not RAW.** We send the keccak256 digest to KMS, not
  the raw transaction bytes. KMS then ECDSA-signs the digest with SHA-256
  internally treating the digest as the message digest (since
  `MessageType=DIGEST`). Switching to `MessageType=RAW` would cause KMS to
  hash again and produce a wrong signature.
- **The asymmetric KMS key must be `ECC_SECG_P256K1`** with key usage
  `SIGN_VERIFY`. NIST P-256 (`ECC_NIST_P256`) is not Ethereum-compatible and
  must be rejected.
- **The public key cache has process-wide scope.** If you add per-call
  options (e.g. signer-specific TTL), be careful not to introduce
  goroutine-unsafe state.

## Testing approach

- **Container-based integration tests** use testcontainers-go to start
  [`nsmithuk/local-kms`](https://github.com/nsmithuk/local-kms), the only
  open-source KMS emulator that supports `ECC_SECG_P256K1` + `ECDSA_SHA_256`.
  Tests create a real KMS key, retrieve the public key, sign a known message,
  and verify with `crypto.Ecrecover` against the derived Ethereum address.
- **Unit tests** cover pure-Go logic (DER↔R‖S conversion, V flipping,
  low-S enforcement) with known test vectors so they run without Docker.
- **Fuzz tests** target `adjustSignatureLength` and the V-recovery path to
  catch malformed-signature edge cases.

## Versioning

Tags follow Go's semantic import versioning. The module path includes the
major-version suffix (`/v3`, `/v4`, …); a breaking change requires both a
new tag and a new module-path suffix.
