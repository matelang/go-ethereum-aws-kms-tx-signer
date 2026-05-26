# Security Policy

## Supported Versions

This module is published as `github.com/matelang/go-ethereum-aws-kms-tx-signer`.
Security fixes will be issued against the latest released major-version tag.
Older patch versions will not be backported unless a maintainer explicitly
indicates so on a release.

| Version          | Supported          |
|------------------|--------------------|
| latest major     | :white_check_mark: |
| previous major   | best-effort        |
| anything older   | :x:                |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:
<https://github.com/matelang/go-ethereum-aws-kms-tx-signer/security/advisories/new>

If you cannot use that channel, email the maintainer at
798365+matelang@users.noreply.github.com with the subject prefix
`[go-ethereum-aws-kms-tx-signer security]` and include:

- A description of the issue and its impact
- Steps to reproduce, ideally with a minimal Go program or test
- Affected version(s) / commit SHA
- Any mitigations or workarounds you have identified

You should expect an acknowledgement within **7 days**. Once a fix is ready a
GitHub Security Advisory will be published, the fix will be released as a new
`vX.Y.Z` tag, and credit will be given to the reporter unless they request
otherwise.

## Scope

In scope:

- Signature forgery or verification bypass triggered by attacker-controlled
  inputs to `NewAwsKmsTransactorWithChainID`, `GetPubKey`, or the EIP-712
  typed-data signer.
- Issues in DER ↔ R‖S signature conversion (`getSignatureFromKms`,
  `adjustSignatureLength`).
- Incorrect V-byte recovery / public-key matching in `getEthereumSignature`.
- Failures to enforce low-S (EIP-2 / ECDSA malleability) before producing the
  final signature.
- Public-key cache correctness issues that could let a rotated/revoked KMS
  key remain usable past its intended lifetime.

Out of scope:

- Vulnerabilities in AWS KMS itself or in the AWS SDK for Go.
- Vulnerabilities in `github.com/ethereum/go-ethereum` (report those upstream).
- Issues that require attacker control over the application's KMS IAM
  policy, KMS key material, or process memory.
- Misconfigured KMS key policies on the consumer side.
