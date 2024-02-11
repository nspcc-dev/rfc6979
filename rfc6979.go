/*
Package rfc6979 is an implementation of RFC 6979's deterministic DSA.

	Such signatures are compatible with standard Digital Signature Algorithm
	(DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA) digital
	signatures and can be processed with unmodified verifiers, which need not be
	aware of the procedure described therein.  Deterministic signatures retain
	the cryptographic security features associated with digital signatures but
	can be more easily implemented in various environments, since they do not
	need access to a source of high-quality randomness.

(https://tools.ietf.org/html/rfc6979)

Provides functions similar to crypto/dsa and crypto/ecdsa.
*/
package rfc6979

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"math/big"
)

// mac returns an HMAC result for the given key and message as well as
// hmac hash instance itself (that can be reused for the same key after reset).
func mac(alg func() hash.Hash, k, m, buf []byte) ([]byte, hash.Hash) {
	h := hmac.New(alg, k)
	h.Write(m)
	return h.Sum(buf[:0]), h
}

// macReuse allows to reuse already initialized hmac for the next
// message using the same key.
func macReuse(h hash.Hash, m, buf []byte) []byte {
	h.Reset()
	h.Write(m)
	return h.Sum(buf[:0])
}

// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(in []byte, qlen int) *big.Int {
	vlen := len(in) * 8
	v := new(big.Int).SetBytes(in)
	if vlen > qlen {
		v.Rsh(v, uint(vlen-qlen))
	}
	return v
}

// bits2IntModQ implements an integer part of bits2octets defined
// in https://tools.ietf.org/html/rfc6979#section-2.3.4
func bits2IntModQ(in []byte, q *big.Int, qlen int) *big.Int {
	z1 := bits2int(in, qlen)
	if z1.Cmp(q) < 0 {
		return z1
	}
	return z1.Sub(z1, q)
}

var one = big.NewInt(1)

// https://tools.ietf.org/html/rfc6979#section-3.2
func generateSecret(q, x *big.Int, alg func() hash.Hash, hash []byte, test func(*big.Int, *big.Int) bool) {
	qlen := q.BitLen()
	holen := alg().Size()
	rolen := (qlen + 7) >> 3

	var bx = make([]byte, 2*rolen)
	x.FillBytes(bx[:rolen]) // int2octets per https://tools.ietf.org/html/rfc6979#section-2.3.3

	var hashInt = bits2IntModQ(hash, q, qlen)
	hashInt.FillBytes(bx[rolen:]) // int2octets per https://tools.ietf.org/html/rfc6979#section-2.3.3

	// Step B
	var v = make([]byte, holen, holen+1+len(bx)) // see appends below
	for i := 0; i < holen; i++ {
		v[i] = 0x01
	}

	// Step C
	k := bytes.Repeat([]byte{0x00}, holen)

	// Step D
	k, _ = mac(alg, k, append(append(v, 0x00), bx...), k)

	// Step E
	v, h := mac(alg, k, v, v)

	// Step F
	k = macReuse(h, append(append(v, 0x01), bx...), k)

	// Step G
	v, h = mac(alg, k, v, v)

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		for len(t) < qlen/8 {
			v = macReuse(h, v, v)
			t = append(t, v...)
		}

		// Step H3
		secret := bits2int(t, qlen)
		if secret.Cmp(one) >= 0 && secret.Cmp(q) < 0 && test(secret, hashInt) {
			return
		}
		k, _ = mac(alg, k, append(v, 0x00), k)
		v, h = mac(alg, k, v, v)
	}
}
