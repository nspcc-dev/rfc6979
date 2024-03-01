package rfc6979

import (
	"crypto/dsa" //nolint:staticcheck
	"hash"
	"math/big"
)

// SignDSA signs an arbitrary length hash (which should be the result of hashing
// a larger message) using the private key, priv. It returns the signature as a
// pair of integers.
//
// Deprecated: crypto/dsa package is deprecated in Go, so please swtich to ECDSA.
// This method can be removed in future versions.
func SignDSA(priv *dsa.PrivateKey, hash []byte, alg func() hash.Hash) (r, s *big.Int, err error) {
	n := priv.Q.BitLen()
	if n&7 != 0 {
		err = dsa.ErrInvalidPublicKey
		return
	}

	generateSecret(priv.Q, priv.X, alg, hash, func(k *big.Int, z *big.Int, _ []byte) bool {
		r = new(big.Int).Exp(priv.G, k, priv.P)
		r.Mod(r, priv.Q)

		if r.Sign() == 0 {
			return false
		}

		inv := k.ModInverse(k, priv.Q)

		s = new(big.Int).Mul(priv.X, r)
		s.Add(s, z)
		s.Mod(s, priv.Q)
		s.Mul(s, inv)
		s.Mod(s, priv.Q)

		return s.Sign() != 0
	})

	return
}
