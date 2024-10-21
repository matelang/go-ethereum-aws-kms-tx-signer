package ethawskmssigner

import (
	"context"
	"fmt"
	"math/big"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type AwsKmsTypedDataSigner struct {
	svc     *kms.Client
	keyId   string
	pubkey  []byte
	address common.Address
	chainID *big.Int
}

func NewAwsKmsTypedDataSigner(svc *kms.Client, keyId string, chainID *big.Int) (*AwsKmsTypedDataSigner, error) {
	pubkey, err := GetPubKeyCtx(context.Background(), svc, keyId)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := secp256k1.S256().Marshal(pubkey.X, pubkey.Y)

	keyAddr := crypto.PubkeyToAddress(*pubkey)
	if chainID == nil {
		return nil, bind.ErrNoChainID
	}

	signer := &AwsKmsTypedDataSigner{
		svc:     svc,
		keyId:   keyId,
		pubkey:  pubKeyBytes,
		address: keyAddr,
		chainID: chainID,
	}

	return signer, nil
}

func (s *AwsKmsTypedDataSigner) SignTypedData(typedData apitypes.TypedData) ([]byte, error) {
	hash, err := EncodeForSigning(typedData)
	if err != nil {
		return nil, err
	}

	rBytes, sBytes, err := getSignatureFromKms(context.Background(), s.svc, s.keyId, hash.Bytes())
	if err != nil {
		return nil, err
	}

	// Adjust S value from signature according to Ethereum standard
	sBigInt := new(big.Int).SetBytes(sBytes)
	if sBigInt.Cmp(secp256k1HalfN) > 0 {
		sBytes = new(big.Int).Sub(secp256k1N, sBigInt).Bytes()
	}

	signature, err := getEthereumSignature(s.pubkey, hash.Bytes(), rBytes, sBytes)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (s *AwsKmsTypedDataSigner) Address() common.Address {
	return s.address
}

func (s *AwsKmsTypedDataSigner) ChainID() *big.Int {
	return s.chainID
}

// encodeForSigning - Encoding the typed data
func EncodeForSigning(typedData apitypes.TypedData) (hash common.Hash, err error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return
	}
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	hash = common.BytesToHash(crypto.Keccak256(rawData))
	return
}

// VerifySig - Verify signature with recovered address
func VerifySig(from, sigHex string, msg []byte) bool {
	sig := hexutil.MustDecode(sigHex)
	//msg = accounts.TextHash(msg)
	if sig[crypto.RecoveryIDOffset] == 27 || sig[crypto.RecoveryIDOffset] == 28 {
		sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1
	}
	recovered, err := crypto.SigToPub(msg, sig)
	recoveredAddr1 := crypto.PubkeyToAddress(*recovered)
	fmt.Printf("the recovered address: %v \n", recoveredAddr1)
	if err != nil {
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	return from == recoveredAddr.Hex()
}
