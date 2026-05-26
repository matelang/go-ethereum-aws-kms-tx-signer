package ethawskmssigner_test

import (
	"context"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	ethawskmssigner "github.com/matelang/go-ethereum-aws-kms-tx-signer/v2"
)

// secp256k1HalfN is duplicated from signer.go for in-test access; keeping
// it as a test-local constant avoids exposing it as public API.
var secp256k1HalfN = new(big.Int).Div(crypto.S256().Params().N, big.NewInt(2))

func TestNewAwsKmsTransactor_NoChainID(t *testing.T) {
	// nil chainID must be rejected before any KMS call, so no svc needed.
	_, err := ethawskmssigner.NewAwsKmsTransactorWithChainID(nil, "any-key", nil)
	if !errors.Is(err, bind.ErrNoChainID) {
		t.Fatalf("expected bind.ErrNoChainID, got %v", err)
	}
}

func TestNewAwsKmsTransactor_SignsAndRecovers(t *testing.T) {
	client, keyID := startLocalKMS(t)
	chainID := big.NewInt(1)

	opts, err := ethawskmssigner.NewAwsKmsTransactorWithChainID(client, keyID, chainID)
	if err != nil {
		t.Fatalf("NewAwsKmsTransactorWithChainID: %v", err)
	}
	if (opts.From == common.Address{}) {
		t.Fatal("zero From address")
	}
	if opts.Signer == nil {
		t.Fatal("nil Signer")
	}

	to := common.HexToAddress("0x000000000000000000000000000000000000beef")
	tx := types.NewTransaction(42, to, big.NewInt(100), 21000, big.NewInt(1_000_000_000), nil)

	signed, err := opts.Signer(opts.From, tx)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	signer := types.LatestSignerForChainID(chainID)
	sender, err := types.Sender(signer, signed)
	if err != nil {
		t.Fatalf("recover sender: %v", err)
	}
	if sender != opts.From {
		t.Errorf("recovered sender %s != From %s", sender.Hex(), opts.From.Hex())
	}
}

func TestNewAwsKmsTransactor_RejectsForeignAddress(t *testing.T) {
	client, keyID := startLocalKMS(t)
	chainID := big.NewInt(1)

	opts, err := ethawskmssigner.NewAwsKmsTransactorWithChainID(client, keyID, chainID)
	if err != nil {
		t.Fatalf("NewAwsKmsTransactorWithChainID: %v", err)
	}

	foreign := common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	tx := types.NewTransaction(0, foreign, big.NewInt(1), 21000, big.NewInt(1_000_000_000), nil)

	_, err = opts.Signer(foreign, tx)
	if !errors.Is(err, bind.ErrNotAuthorized) {
		t.Fatalf("expected bind.ErrNotAuthorized, got %v", err)
	}
}

// Signatures must always be low-S (EIP-2). KMS may return either half;
// normalizeS must flip high-S signatures.
func TestNewAwsKmsTransactor_LowS(t *testing.T) {
	client, keyID := startLocalKMS(t)
	chainID := big.NewInt(1)

	opts, err := ethawskmssigner.NewAwsKmsTransactorWithChainID(client, keyID, chainID)
	if err != nil {
		t.Fatalf("NewAwsKmsTransactor: %v", err)
	}

	for i := range 5 {
		tx := types.NewTransaction(
			uint64(i), common.Address{}, big.NewInt(1), 21000, big.NewInt(1_000_000_000), nil,
		)
		signed, err := opts.Signer(opts.From, tx)
		if err != nil {
			t.Fatalf("sign tx %d: %v", i, err)
		}
		_, _, s := signed.RawSignatureValues()
		if s.Cmp(secp256k1HalfN) > 0 {
			t.Errorf("tx %d: high-S signature %s > %s", i, s, secp256k1HalfN)
		}
	}
}

// TestSigning is the live KMS+Ethereum-RPC integration test. Set
// INTEGRATION_KEY_ID and INTEGRATION_ETH_RPC to run it; otherwise it
// is skipped. The container-based tests above cover the same code path
// without needing AWS credentials.
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
