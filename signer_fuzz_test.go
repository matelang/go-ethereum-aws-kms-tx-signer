package ethawskmssigner

import (
	"bytes"
	"math/big"
	"testing"
)

// FuzzAdjustSignatureLength explores the DER R/S length normaliser. The
// property under test: for any input, the output is at least 32 bytes
// long AND represents the same unsigned big-int value as the input.
func FuzzAdjustSignatureLength(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add(bytes.Repeat([]byte{0xff}, 31))
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add(append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x01}, 32)...))
	f.Add(append([]byte{0x00}, bytes.Repeat([]byte{0xff}, 32)...))

	f.Fuzz(func(t *testing.T, buf []byte) {
		out := adjustSignatureLength(buf)
		if len(out) < rsLen {
			t.Errorf("output length %d < %d for input %x", len(out), rsLen, buf)
		}
		inVal := new(big.Int).SetBytes(buf)
		outVal := new(big.Int).SetBytes(out)
		if inVal.Cmp(outVal) != 0 {
			t.Errorf("value not preserved: input=%s output=%s (raw in=%x out=%x)", inVal, outVal, buf, out)
		}
	})
}

// FuzzNormalizeS explores the low-S enforcement. For any s in [1, N-1],
// the output must be ≤ N/2.
func FuzzNormalizeS(f *testing.F) {
	f.Add([]byte{0x01})
	f.Add(secp256k1HalfN.Bytes())
	f.Add(new(big.Int).Add(secp256k1HalfN, big.NewInt(1)).Bytes())
	f.Add(new(big.Int).Sub(secp256k1N, big.NewInt(1)).Bytes())

	f.Fuzz(func(t *testing.T, buf []byte) {
		sBig := new(big.Int).SetBytes(buf)
		if sBig.Sign() == 0 || sBig.Cmp(secp256k1N) >= 0 {
			return // out-of-range input; KMS would never produce this.
		}
		out := normalizeS(buf)
		outBig := new(big.Int).SetBytes(out)
		if outBig.Cmp(secp256k1HalfN) > 0 {
			t.Errorf("output is high-S: %s > N/2 (input s=%s)", outBig, sBig)
		}
		if outBig.Sign() == 0 {
			t.Errorf("output is zero (input s=%s)", sBig)
		}
	})
}
