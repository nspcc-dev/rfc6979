package rfc6979

import (
	"crypto/ecdsa"
	"hash"
	"math/big"
)

// SignECDSA signs an arbitrary length hash (which should be the result of
// hashing a larger message) using the private key, priv. It returns the
// signature as a pair of integers.
//
// Will panic if invalid private key (>N for the curve) is passed.
func SignECDSA(priv *ecdsa.PrivateKey, hash []byte, alg func() hash.Hash) (r, s *big.Int) {
	c := priv.PublicKey.Curve
	N := c.Params().N

	generateSecret(N, priv.D, alg, hash, func(k *big.Int, e *big.Int) bool {
		inv := new(big.Int).ModInverse(k, N)
		r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
		r.Mod(r, N)

		if r.Sign() == 0 {
			return false
		}

		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, inv)
		s.Mod(s, N)

		return s.Sign() != 0
	})

	return
}
