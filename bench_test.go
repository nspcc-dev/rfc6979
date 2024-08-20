package rfc6979_test

import (
	"crypto/sha256"
	"testing"

	"github.com/nspcc-dev/rfc6979"
)

func BenchmarkECDSASign(b *testing.B) {
	const msg = "Hello world!"

	h := sha256.Sum256([]byte(msg))
	b.ResetTimer()
	for range b.N {
		_, _ = rfc6979.SignECDSA(p256.key, h[:], sha256.New)
	}
}
