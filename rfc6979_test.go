package rfc6979

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

// https://tools.ietf.org/html/rfc6979#appendix-A.1
func TestGenerateSecret(t *testing.T) {
	q, _ := new(big.Int).SetString("4000000000000000000020108A2E0CC0D99F8A5EF", 16)

	x, _ := new(big.Int).SetString("09A4D6792295A7F730FC3F2B49CBC0F62E862272F", 16)

	hash, _ := hex.DecodeString("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")

	expected, _ := new(big.Int).SetString("23AF4074C90A02B3FE61D286D5C87F425E6BDD81B", 16)
	var actual *big.Int
	generateSecret(q, x, sha256.New, hash, func(k *big.Int, _ *big.Int, _ []byte) bool {
		actual = k
		return true
	})

	if actual.Cmp(expected) != 0 {
		t.Errorf("Expected %x, got %x", expected, actual)
	}
}
