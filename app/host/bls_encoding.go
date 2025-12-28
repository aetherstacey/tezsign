package main

import (
	"crypto/sha256"
	"errors"

	"github.com/mr-tron/base58"
)

const blsSignatureBytes = 96 // BLS12-381 G2 compressed size

var (
	pfxBLSignature = []byte{40, 171, 64, 207} // "BLsig"

	ErrSigNot96Bytes = errors.New("signature must be 96-byte G2 compressed")
)

// EncodeBLSignature encodes a 96-byte BLS12-381 signature (G2 compressed) as Tezos "BLsig..." Base58Check.
func EncodeBLSignature(sigBytes []byte) (string, error) {
	if len(sigBytes) != blsSignatureBytes {
		return "", ErrSigNot96Bytes
	}
	return b58CheckEncode(pfxBLSignature, sigBytes), nil
}

// Base58Check(prefix || payload || doubleSHA256(prefix||payload)[0:4])
func b58CheckEncode(prefix, payload []byte) string {
	n := len(prefix) + len(payload)
	buf := make([]byte, n+4)
	copy(buf, prefix)
	copy(buf[len(prefix):], payload)

	sum1 := sha256.Sum256(buf[:n])
	sum2 := sha256.Sum256(sum1[:])
	copy(buf[n:], sum2[:4])

	return base58.Encode(buf)
}
