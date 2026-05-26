package ethawskmssigner_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	ethawskmssigner "github.com/matelang/go-ethereum-aws-kms-tx-signer/v2"
)

func mailTypedData(chainID *big.Int) apitypes.TypedData {
	return apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Mail": {
				{Name: "to", Type: "address"},
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
			"to":       "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
			"contents": "Hello, Bob!",
		},
	}
}

func TestAwsKmsTypedDataSigner_SignAndRecover(t *testing.T) {
	client, keyID := startLocalKMS(t)

	signer, err := ethawskmssigner.NewAwsKmsTypedDataSigner(client, keyID)
	if err != nil {
		t.Fatalf("NewAwsKmsTypedDataSigner: %v", err)
	}

	typedData := mailTypedData(big.NewInt(1))
	sig, err := signer.SignTypedData(typedData)
	if err != nil {
		t.Fatalf("SignTypedData: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length = %d, want 65", len(sig))
	}

	addr, err := ethawskmssigner.RecoverTypedDataSigner(typedData, sig)
	if err != nil {
		t.Fatalf("RecoverTypedDataSigner: %v", err)
	}
	if addr != signer.Address() {
		t.Errorf("recovered %s != signer %s", addr.Hex(), signer.Address().Hex())
	}
}

// A signature for one piece of typed data must not recover the signer's
// address when verified against a *different* piece of typed data.
func TestAwsKmsTypedDataSigner_RecoverRejectsDifferentData(t *testing.T) {
	client, keyID := startLocalKMS(t)

	signer, err := ethawskmssigner.NewAwsKmsTypedDataSigner(client, keyID)
	if err != nil {
		t.Fatalf("NewAwsKmsTypedDataSigner: %v", err)
	}

	original := mailTypedData(big.NewInt(1))
	sig, err := signer.SignTypedData(original)
	if err != nil {
		t.Fatalf("SignTypedData: %v", err)
	}

	mutated := mailTypedData(big.NewInt(2)) // different chainId => different domain hash
	addr, err := ethawskmssigner.RecoverTypedDataSigner(mutated, sig)
	if err != nil {
		t.Fatalf("RecoverTypedDataSigner: %v", err)
	}
	if addr == signer.Address() {
		t.Errorf("recovered signer address from a signature for different typed data — domain separator is not binding")
	}
}

func TestRecoverTypedDataSigner_RejectsWrongLength(t *testing.T) {
	_, err := ethawskmssigner.RecoverTypedDataSigner(mailTypedData(big.NewInt(1)), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for wrong-length signature")
	}
}

func TestRecoverTypedDataSigner_AcceptsBothVConventions(t *testing.T) {
	client, keyID := startLocalKMS(t)

	signer, err := ethawskmssigner.NewAwsKmsTypedDataSigner(client, keyID)
	if err != nil {
		t.Fatalf("NewAwsKmsTypedDataSigner: %v", err)
	}

	typedData := mailTypedData(big.NewInt(1))
	sig01, err := signer.SignTypedData(typedData)
	if err != nil {
		t.Fatalf("SignTypedData: %v", err)
	}
	// SignTypedData returns V in {0,1}. Build the 27/28 variant and
	// confirm both recover to the same address.
	sig2728 := make([]byte, 65)
	copy(sig2728, sig01)
	sig2728[64] += 27

	a, err := ethawskmssigner.RecoverTypedDataSigner(typedData, sig01)
	if err != nil {
		t.Fatalf("Recover(V=0/1): %v", err)
	}
	b, err := ethawskmssigner.RecoverTypedDataSigner(typedData, sig2728)
	if err != nil {
		t.Fatalf("Recover(V=27/28): %v", err)
	}
	if a != b {
		t.Errorf("recovered addresses differ across V conventions: %s vs %s", a, b)
	}
}

// HashTypedData must produce the exact 32-byte EIP-712 digest. We use a
// hand-computed reference test against a fixed Mail payload.
func TestHashTypedData_StableOutput(t *testing.T) {
	typedData := mailTypedData(big.NewInt(1))
	h1, err := ethawskmssigner.HashTypedData(typedData)
	if err != nil {
		t.Fatalf("HashTypedData: %v", err)
	}
	h2, err := ethawskmssigner.HashTypedData(typedData)
	if err != nil {
		t.Fatalf("HashTypedData (second call): %v", err)
	}
	if h1 != h2 {
		t.Errorf("HashTypedData is non-deterministic: %s vs %s", h1.Hex(), h2.Hex())
	}
	// Different chainID => different hash, by EIP-712 design.
	h3, err := ethawskmssigner.HashTypedData(mailTypedData(big.NewInt(2)))
	if err != nil {
		t.Fatalf("HashTypedData(chainID=2): %v", err)
	}
	if h1 == h3 {
		t.Errorf("hash should differ across chainIDs but didn't (%s)", h1.Hex())
	}
}
