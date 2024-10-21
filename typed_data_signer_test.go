package ethawskmssigner_test

import (
	"context"
	"testing"

	ethawskmssigner "github.com/0xSyndr/go-ethereum-aws-kms-tx-signer"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/stretchr/testify/assert"
)

func TestSignTypedData(t *testing.T) {
	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("ap-northeast-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			"<AWS_ACCESS_KEY_ID>",
			"<AWS_SECRET_ACCESS_KEY>",
			"",
		)),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	kmsSvc := kms.NewFromConfig(awsCfg)

	client, err := ethclient.Dial(ethAddr)
	if err != nil {
		t.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	chainID, err := client.ChainID(ctx)
	if err != nil {
		t.Fatalf("Failed to get chain ID: %v", err)
	}

	signer, err := ethawskmssigner.NewAwsKmsTypedDataSigner(kmsSvc, keyId, chainID)
	if err != nil {
		t.Fatalf("Failed to create AwsKmsTypedDataSigner: %v", err)
	}

	// EIP-712 typed data
	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Person": {
				{Name: "name", Type: "string"},
				{Name: "wallet", Type: "address"},
			},
			"Mail": {
				{Name: "from", Type: "Person"},
				{Name: "to", Type: "Person"},
				{Name: "contents", Type: "string"},
			},
		},
		PrimaryType: "Mail",
		Domain: apitypes.TypedDataDomain{
			Name:              "Ether Mail",
			Version:           "1",
			ChainId:           (*math.HexOrDecimal256)(chainID),
			VerifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		},
		Message: apitypes.TypedDataMessage{
			"from": map[string]interface{}{
				"name":   "Cow",
				"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
			},
			"to": map[string]interface{}{
				"name":   "Bob",
				"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
			},
			"contents": "Hello, Bob!",
		},
	}

	signature, err := signer.SignTypedData(typedData)
	if err != nil {
		t.Fatalf("Failed to sign typed data: %v", err)
	}

	// Verify the signature length
	assert.Equal(t, 65, len(signature), "Signature length should be 65 bytes")

	// Print the signature for manual verification if needed
	t.Logf("Signature: 0x%s", hexutil.Encode(signature))

	hash, err := ethawskmssigner.EncodeForSigning(typedData)
	if err != nil {
		t.Fatalf("Failed to encode typed data for signing: %v", err)
	}
	recovered := ethawskmssigner.VerifySig(signer.Address().Hex(), hexutil.Encode(signature), hash.Bytes())
	assert.True(t, recovered, "Signature should be verified")

	recovered = ethawskmssigner.VerifySig(anotherEthAddr, hexutil.Encode(signature), hash.Bytes())
	assert.False(t, recovered, "Signature should fail verification with wrong address")
}
