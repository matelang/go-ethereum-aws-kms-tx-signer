![gopher](gopher.png)

# AWS KMS transaction signer for go-ethereum

```
⚠️This repo was recently moved to `matelang/go-ethereum-aws-kms-tx-signer` 
from `welthee/go-ethereum-aws-kms-tx-signer`.

Update your import paths accordingly.
```

This little package eases integration with AWS KMS in your GoLang Ethereum project, by extending the functionality
offered by the official go-ethereum library.

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

# Further reading
* [Signing and Verifying Ethereum Signatures](https://yos.io/2018/11/16/ethereum-signatures/)
* [EIP-155: Simple replay attack protection](https://eips.ethereum.org/EIPS/eip-155)
* [The Dark Side of the Elliptic Curve - Signing Ethereum Transactions with AWS KMS in JavaScript](https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81)

# History
This package was originally created for [welthee](https://welthee.com), and donated to the community as open source.
Since the company could not provide a maintainer for this package, it was moved to the [matelang], where it is now maintained.
I am the original author of this package, and I am happy to continue maintaining it.
