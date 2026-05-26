package ethawskmssigner_test

import (
	"context"
	"math/big"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	ethawskmssigner "github.com/matelang/go-ethereum-aws-kms-tx-signer/v2"
)

// Set INTEGRATION_KEY_ID, INTEGRATION_ETH_RPC, and (optionally) INTEGRATION_RECIPIENT
// to run TestSigning against a real KMS key and Ethereum endpoint. Without these,
// the test is skipped.
//
// Container-based tests against nsmithuk/local-kms are added in a follow-up PR.
func TestSigning(t *testing.T) {
	keyID := os.Getenv("INTEGRATION_KEY_ID")
	rpcURL := os.Getenv("INTEGRATION_ETH_RPC")
	if keyID == "" || rpcURL == "" {
		t.Skip("set INTEGRATION_KEY_ID and INTEGRATION_ETH_RPC to run the live KMS+Ethereum integration test")
	}
	recipient := os.Getenv("INTEGRATION_RECIPIENT")
	if recipient == "" {
		recipient = "0xeB7eb6c156ac20a9c45beFDC95F1A13625B470b7"
	}

	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
	kmsSvc := kms.NewFromConfig(awsCfg)

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		t.Fatalf("dial %s: %v", rpcURL, err)
	}

	chainID, err := client.ChainID(ctx)
	if err != nil {
		t.Fatalf("chain id: %v", err)
	}

	transactOpts, err := ethawskmssigner.NewAwsKmsTransactorWithChainIDCtx(ctx, kmsSvc, keyID, chainID)
	if err != nil {
		t.Fatalf("new transactor: %v", err)
	}

	nonce, err := client.PendingNonceAt(ctx, transactOpts.From)
	if err != nil {
		t.Fatalf("pending nonce: %v", err)
	}

	toAddress := common.HexToAddress(recipient)
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		t.Fatalf("suggest gas price: %v", err)
	}
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{To: &toAddress})
	if err != nil {
		t.Fatalf("estimate gas: %v", err)
	}

	tx := types.NewTransaction(nonce, toAddress, big.NewInt(10), gasLimit, gasPrice, nil)
	signedTx, err := transactOpts.Signer(transactOpts.From, tx)
	if err != nil {
		t.Fatalf("sign tx: %v", err)
	}

	if err := client.SendTransaction(ctx, signedTx); err != nil {
		t.Fatalf("send tx: %v", err)
	}
}
