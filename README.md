![gopher](gopher.png)

# AWS KMS transaction signer for go-ethereum

[![Go](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/go.yml/badge.svg)](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/go.yml)
[![Lint](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/lint.yml/badge.svg)](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/lint.yml)
[![Security](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/security.yml/badge.svg)](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/security.yml)
[![CodeQL](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/codeql.yml/badge.svg)](https://github.com/matelang/go-ethereum-aws-kms-tx-signer/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/matelang/go-ethereum-aws-kms-tx-signer/badge)](https://scorecard.dev/viewer/?uri=github.com/matelang/go-ethereum-aws-kms-tx-signer)
[![Go Reference](https://pkg.go.dev/badge/github.com/matelang/go-ethereum-aws-kms-tx-signer/v2.svg)](https://pkg.go.dev/github.com/matelang/go-ethereum-aws-kms-tx-signer/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/matelang/go-ethereum-aws-kms-tx-signer/v2)](https://goreportcard.com/report/github.com/matelang/go-ethereum-aws-kms-tx-signer/v2)
[![License](https://img.shields.io/github/license/matelang/go-ethereum-aws-kms-tx-signer)](LICENSE)

> Now maintained at `github.com/matelang/go-ethereum-aws-kms-tx-signer/v2`.
> Consumers on the previous `github.com/welthee/...v2` path should
> update their imports — the welthee path is no longer maintained.

This package eases integration with AWS KMS in your Go Ethereum project,
by extending the functionality offered by the official `go-ethereum`
library.

## Import

```go
import "github.com/matelang/go-ethereum-aws-kms-tx-signer/v2"
```

## Usage
In order to sign Ethereum transactions with an AWS KMS key you need to create a KMS key in AWS, and grant your
application's principal access to use it.

Then, modify your Ethereum transactor code to use the `bind.TransactOpts` that this library returns.

### Create an AWS KMS key
Create an AWS KMS Assymetric key with key usage of `SIGN_VERIFY` and spec `ECC_SECG_P256K1`. Make sure that you add an
appropriate key policy granting your code the following permissions:
`kms:GetPublicKey`, `kms:Sign`.

Example key policy:
```json
{
  "Sid": "AllowSignAndGetPublicKey",
  "Effect": "Allow",
  "Resource": "*",
  "Principal": {
    "AWS": [
      "arn:aws:iam::111122223333:user/CMKUser",
      "arn:aws:iam::111122223333:role/CMKRole",
      "arn:aws:iam::444455556666:root"
    ]
  },
  "Action": [
    "kms:Sign",
    "kms:GetPublicKey"
  ]
}
```

### Your transactor code
The `abigen` tool generates bindings that are able to directly operate with the `*bind.TransactOpts` type.

For instance an IERC20 transactor integrated with the KMS signer would look like this:
```go
var client *ethclient.client
var kmsSvc *kms.KMS
var chainID *big.Int
var erc20Address common.Address

transactor, _ := internal.NewIERC20Transactor(erc20Address, client)

transactOpts := ethawskmssigner.NewAwsKmsTransactorWithChainID(kmsSvc, keyId, chainId)

tx, err := transactor.Transfer(transactOpts, toAddress, big.NewInt(amountInt))
```
Note how the `ethawskmssigner.NewAwsKmsTransactorWithChainID(...)` returns a ready to use `*bind.TransactOpts`.

In order to use in manually constructed transactions, you can use the Signer to sign your transaction yourself.
Example:
```go
transactOpts, _ := ethawskmssigner.NewAwsKmsTransactorWithChainID(kmsSvc, keyId, clChainId)
tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)
signedTx, _ := transactOpts.Signer(transactOpts.From, tx)
err = client.SendTransaction(context.TODO(), signedTx)
```

The transactor uses `types.LatestSignerForChainID` internally, so legacy,
EIP-2930, EIP-1559, and EIP-4844 transactions are all supported without
any extra wiring.

## Signing EIP-712 typed data

For off-chain typed-data flows (Permit, order books, off-chain auth,
etc.) use `AwsKmsTypedDataSigner`:

```go
signer, err := ethawskmssigner.NewAwsKmsTypedDataSigner(kmsSvc, keyId)
if err != nil {
    log.Fatal(err)
}

typedData := apitypes.TypedData{
    Types: apitypes.Types{
        "EIP712Domain": {{Name: "name", Type: "string"}, /* ... */ },
        "Mail":         {{Name: "to", Type: "address"}, {Name: "contents", Type: "string"}},
    },
    PrimaryType: "Mail",
    Domain:      apitypes.TypedDataDomain{ /* name, version, chainId, verifyingContract */ },
    Message:     apitypes.TypedDataMessage{"to": "0x...", "contents": "Hello"},
}

signature, err := signer.SignTypedData(typedData)         // returns 65 bytes, V in {0,1}
recovered, err := ethawskmssigner.RecoverTypedDataSigner(typedData, signature)
// recovered == signer.Address()
```

## Testing

Most tests run an [`nsmithuk/local-kms`](https://github.com/nsmithuk/local-kms)
container via [testcontainers-go](https://github.com/testcontainers/testcontainers-go),
so they do not need real AWS credentials. They do need Docker (or a
compatible Docker socket — Podman works) on the machine running `go test`.

```bash
# All tests, including the container-based suite
go test -race ./...

# Skip container tests (only in-process unit tests run)
go test -short ./...
```

`TestSigning` is a live KMS + Ethereum RPC integration test, kept for
the case where you want to send a real transaction. Set:

```bash
export INTEGRATION_KEY_ID=<your KMS key id>
export INTEGRATION_ETH_RPC=<your Ethereum RPC URL>
go test -run TestSigning ./...
```

## Versioning

Tags follow Go's [semantic import versioning](https://go.dev/ref/mod#versions).
The module path includes the major-version suffix, so a major-version bump
requires updating both the tag (`vX.Y.Z`) and the import path
(`.../vX`).

| Module path                                            | Status                  |
|--------------------------------------------------------|-------------------------|
| `github.com/matelang/go-ethereum-aws-kms-tx-signer/v2` | **current**, maintained |
| `github.com/welthee/go-ethereum-aws-kms-tx-signer/v2`  | abandoned upstream      |
| `github.com/welthee/go-ethereum-aws-kms-tx-signer`     | `v0.1.x` historical     |

## Further reading

- [Signing and Verifying Ethereum Signatures](https://yos.io/2018/11/16/ethereum-signatures/)
- [EIP-155: Simple replay attack protection](https://eips.ethereum.org/EIPS/eip-155)
- [The Dark Side of the Elliptic Curve - Signing Ethereum Transactions with AWS KMS in JavaScript](https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81)

## History

This package was originally created for [welthee](https://welthee.com)
and donated to the community as open source. Since the company could not
provide a maintainer, it was moved to `matelang/` where it continues to
be maintained by the original author.
