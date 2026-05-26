package ethawskmssigner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

const (
	awsKmsSignOperationMessageType      = "DIGEST"
	awsKmsSignOperationSigningAlgorithm = "ECDSA_SHA_256"

	signatureLen = 65
	rsLen        = 32
)

var keyCache = newPubKeyCache()

var (
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

type asn1EcPublicKey struct {
	EcPublicKeyInfo asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type asn1EcPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

type asn1EcSig struct {
	R asn1.RawValue
	S asn1.RawValue
}

// NewAwsKmsTransactorWithChainID returns a *bind.TransactOpts whose Signer
// callback signs Ethereum transactions with the given KMS-stored secp256k1
// key. Uses context.Background internally; prefer the *Ctx variant if you
// need cancellation.
func NewAwsKmsTransactorWithChainID(
	svc *kms.Client, keyID string, chainID *big.Int,
) (*bind.TransactOpts, error) {
	return NewAwsKmsTransactorWithChainIDCtx(context.Background(), svc, keyID, chainID)
}

// NewAwsKmsTransactorWithChainIDCtx is the context-aware constructor.
// The supplied context is captured by the returned Signer callback and used
// for every KMS Sign call it makes.
func NewAwsKmsTransactorWithChainIDCtx(
	ctx context.Context, svc *kms.Client, keyID string, chainID *big.Int,
) (*bind.TransactOpts, error) {
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}

	pubkey, err := GetPubKeyCtx(ctx, svc, keyID)
	if err != nil {
		return nil, err
	}
	pubKeyBytes := crypto.FromECDSAPub(pubkey)
	keyAddr := crypto.PubkeyToAddress(*pubkey)

	signer := types.LatestSignerForChainID(chainID)

	signerFn := func(address common.Address, tx *types.Transaction) (*types.Transaction, error) {
		if address != keyAddr {
			return nil, bind.ErrNotAuthorized
		}

		txHashBytes := signer.Hash(tx).Bytes()

		rBytes, sBytes, err := getSignatureFromKms(ctx, svc, keyID, txHashBytes)
		if err != nil {
			return nil, err
		}
		sBytes = normalizeS(sBytes)

		signature, err := getEthereumSignature(pubKeyBytes, txHashBytes, rBytes, sBytes)
		if err != nil {
			return nil, err
		}

		return tx.WithSignature(signer, signature)
	}

	return &bind.TransactOpts{
		From:    keyAddr,
		Signer:  signerFn,
		Context: ctx,
	}, nil
}

func getPublicKeyDerBytesFromKMS(ctx context.Context, svc *kms.Client, keyID string) ([]byte, error) {
	getPubKeyOutput, err := svc.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "can not get public key from KMS for KeyId=%s", keyID)
	}

	var asn1pubk asn1EcPublicKey
	_, err = asn1.Unmarshal(getPubKeyOutput.PublicKey, &asn1pubk)
	if err != nil {
		return nil, errors.Wrapf(err, "can not parse asn1 public key for KeyId=%s", keyID)
	}

	return asn1pubk.PublicKey.Bytes, nil
}

func getSignatureFromKms(
	ctx context.Context, svc *kms.Client, keyID string, txHashBytes []byte,
) ([]byte, []byte, error) {
	signInput := &kms.SignInput{
		KeyId:            aws.String(keyID),
		SigningAlgorithm: awsKmsSignOperationSigningAlgorithm,
		MessageType:      awsKmsSignOperationMessageType,
		Message:          txHashBytes,
	}

	signOutput, err := svc.Sign(ctx, signInput)
	if err != nil {
		return nil, nil, err
	}

	var sigAsn1 asn1EcSig
	_, err = asn1.Unmarshal(signOutput.Signature, &sigAsn1)
	if err != nil {
		return nil, nil, err
	}

	return sigAsn1.R.Bytes, sigAsn1.S.Bytes, nil
}

// getEthereumSignature builds the canonical 65-byte R||S||V Ethereum
// signature, trying V=0 then V=1 to find the recovery byte that recovers
// expectedPublicKeyBytes. Returns an error if neither recovers it.
func getEthereumSignature(expectedPublicKeyBytes, txHash, r, s []byte) ([]byte, error) {
	signature := make([]byte, signatureLen)
	copy(signature[0:rsLen], adjustSignatureLength(r))
	copy(signature[rsLen:2*rsLen], adjustSignatureLength(s))

	for _, v := range []byte{0, 1} {
		signature[signatureLen-1] = v
		recovered, err := crypto.Ecrecover(txHash, signature)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(recovered, expectedPublicKeyBytes) {
			out := make([]byte, signatureLen)
			copy(out, signature)
			return out, nil
		}
	}
	return nil, errors.New("can not reconstruct public key from sig")
}

// normalizeS enforces low-S per EIP-2 / ECDSA malleability: if s > N/2,
// replace it with N - s. KMS returns whichever half the underlying library
// produces; Ethereum rejects high-S signatures.
func normalizeS(s []byte) []byte {
	sBig := new(big.Int).SetBytes(s)
	if sBig.Cmp(secp256k1HalfN) > 0 {
		return new(big.Int).Sub(secp256k1N, sBig).Bytes()
	}
	return s
}

// GetPubKey returns the secp256k1 public key for a KMS key ID.
// Results are process-wide cached, see pubkey_cache.go.
func GetPubKey(svc *kms.Client, keyID string) (*ecdsa.PublicKey, error) {
	return GetPubKeyCtx(context.Background(), svc, keyID)
}

// GetPubKeyCtx is the context-aware variant of GetPubKey.
func GetPubKeyCtx(ctx context.Context, svc *kms.Client, keyID string) (*ecdsa.PublicKey, error) {
	if pubkey := keyCache.Get(keyID); pubkey != nil {
		return pubkey, nil
	}

	pubKeyBytes, err := getPublicKeyDerBytesFromKMS(ctx, svc, keyID)
	if err != nil {
		return nil, err
	}

	pubkey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "can not construct secp256k1 public key from key bytes")
	}
	keyCache.Add(keyID, pubkey)
	return pubkey, nil
}

// adjustSignatureLength left-trims ASN.1 leading-zero sign bytes from the
// R or S component returned by KMS and left-pads the result to 32 bytes.
// Buffers already at or above 32 bytes are returned unchanged so a
// malformed input is detectable upstream rather than silently truncated.
func adjustSignatureLength(buffer []byte) []byte {
	buffer = bytes.TrimLeft(buffer, "\x00")
	if len(buffer) >= rsLen {
		return buffer
	}
	padded := make([]byte, rsLen)
	copy(padded[rsLen-len(buffer):], buffer)
	return padded
}
