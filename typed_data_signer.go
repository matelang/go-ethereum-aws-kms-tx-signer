package ethawskmssigner

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// AwsKmsTypedDataSigner signs EIP-712 typed data using an AWS KMS
// secp256k1 key. Unlike the transactor returned by
// NewAwsKmsTransactorWithChainID — which signs Ethereum transactions —
// this signs arbitrary off-chain typed data (Permit, order books,
// off-chain auth, etc.).
//
// The chain ID is carried by the EIP-712 domain separator on the
// individual typed-data payload (TypedData.Domain.ChainId) and is not
// configured on the signer itself.
type AwsKmsTypedDataSigner struct {
	svc     *kms.Client
	keyID   string
	pubkey  []byte
	address common.Address
}

// NewAwsKmsTypedDataSigner returns a typed-data signer backed by the
// given KMS key. The KMS key must be an ECC_SECG_P256K1 SIGN_VERIFY key;
// any other key type will produce signatures that recover to the wrong
// address.
func NewAwsKmsTypedDataSigner(svc *kms.Client, keyID string) (*AwsKmsTypedDataSigner, error) {
	return NewAwsKmsTypedDataSignerCtx(context.Background(), svc, keyID)
}

// NewAwsKmsTypedDataSignerCtx is the context-aware variant of
// NewAwsKmsTypedDataSigner.
func NewAwsKmsTypedDataSignerCtx(ctx context.Context, svc *kms.Client, keyID string) (*AwsKmsTypedDataSigner, error) {
	pubkey, err := GetPubKeyCtx(ctx, svc, keyID)
	if err != nil {
		return nil, err
	}
	return &AwsKmsTypedDataSigner{
		svc:     svc,
		keyID:   keyID,
		pubkey:  crypto.FromECDSAPub(pubkey),
		address: crypto.PubkeyToAddress(*pubkey),
	}, nil
}

// Address returns the Ethereum address derived from the KMS key.
func (s *AwsKmsTypedDataSigner) Address() common.Address { return s.address }

// SignTypedData hashes typedData per EIP-712 and signs the result with
// the KMS key. Returns a canonical 65-byte R||S||V Ethereum signature
// (V is 0 or 1, not 27/28; add 27 before calling on-chain
// `ecrecover` if needed).
func (s *AwsKmsTypedDataSigner) SignTypedData(typedData apitypes.TypedData) ([]byte, error) {
	return s.SignTypedDataCtx(context.Background(), typedData)
}

// SignTypedDataCtx is the context-aware variant of SignTypedData.
func (s *AwsKmsTypedDataSigner) SignTypedDataCtx(ctx context.Context, typedData apitypes.TypedData) ([]byte, error) {
	hash, err := HashTypedData(typedData)
	if err != nil {
		return nil, fmt.Errorf("hash typed data: %w", err)
	}
	rBytes, sBytes, err := getSignatureFromKms(ctx, s.svc, s.keyID, hash.Bytes())
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	sBytes = normalizeS(sBytes)
	return getEthereumSignature(s.pubkey, hash.Bytes(), rBytes, sBytes)
}

// HashTypedData returns the EIP-712 hash of the typed data — the
// keccak256 of `\x19\x01 || domainSeparator || hashStruct(message)`.
// This is the value that ends up signed.
func HashTypedData(typedData apitypes.TypedData) (common.Hash, error) {
	domainSep, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash domain: %w", err)
	}
	msgHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return common.Hash{}, fmt.Errorf("hash primary type: %w", err)
	}
	raw := make([]byte, 0, 2+len(domainSep)+len(msgHash))
	raw = append(raw, 0x19, 0x01)
	raw = append(raw, domainSep...)
	raw = append(raw, msgHash...)
	return common.BytesToHash(crypto.Keccak256(raw)), nil
}

// RecoverTypedDataSigner returns the Ethereum address that produced
// signature for the given typed data. The signature must be in the
// canonical 65-byte R||S||V layout returned by SignTypedData; both
// 0/1 and 27/28 V conventions are accepted.
func RecoverTypedDataSigner(typedData apitypes.TypedData, signature []byte) (common.Address, error) {
	if len(signature) != signatureLen {
		return common.Address{}, fmt.Errorf("signature must be %d bytes, got %d", signatureLen, len(signature))
	}
	sig := make([]byte, signatureLen)
	copy(sig, signature)
	switch sig[signatureLen-1] {
	case 27, 28:
		sig[signatureLen-1] -= 27
	}

	hash, err := HashTypedData(typedData)
	if err != nil {
		return common.Address{}, err
	}
	pub, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("recover: %w", err)
	}
	if pub == nil {
		return common.Address{}, errors.New("recovered nil public key")
	}
	return crypto.PubkeyToAddress(*pub), nil
}

