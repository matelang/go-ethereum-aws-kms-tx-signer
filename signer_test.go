package ethawskmssigner_test

import (
	"context"
	"log"
	"math/big"
	"testing"

	ethawskmssigner "github.com/0xSyndr/go-ethereum-aws-kms-tx-signer"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

const keyId = "331c7988-c19b-4e30-8037-530389c92ac0"
const anotherEthAddr = "0xeB7eb6c156ac20a9c45beFDC95F1A13625B470b7"

const ethAddr = "https://ropsten.infura.io/v3/a76d1cb719694e48af1a539ec96f040b"

func TestSigning(t *testing.T) {
	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	kmsSvc := kms.NewFromConfig(awsCfg)

	client, err := ethclient.Dial(ethAddr)
	if err != nil {
		log.Fatal(err)
	}

	clChainId, _ := client.ChainID(ctx)

	transactOpts, err := ethawskmssigner.NewAwsKmsTransactorWithChainIDCtx(ctx, kmsSvc, keyId, clChainId)
	if err != nil {
		log.Fatalf("can not sign: %s", err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), transactOpts.From)
	if err != nil {
		log.Fatal(err)
	}

	toAddress := common.HexToAddress(anotherEthAddr)

	suggestedGasPrice, _ := client.SuggestGasPrice(ctx)
	suggestedGasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{To: &toAddress, Data: nil})
	if err != nil {
		log.Fatal(err)
	}
	value := big.NewInt(10)
	gasLimit := suggestedGasLimit
	gasPrice := suggestedGasPrice

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	signedTx, err := transactOpts.Signer(transactOpts.From, tx)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		log.Fatalf("can not send tx %s", err)
	}
}
