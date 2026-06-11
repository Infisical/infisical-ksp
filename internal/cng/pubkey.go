package cng

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

// CNG public-key blob magics (from bcrypt.h). Stored little-endian, like all CNG ULONGs.
const (
	magicRSAPublic    = 0x31415352 // BCRYPT_RSAPUBLIC_MAGIC ("RSA1")
	magicECDSAPubP256 = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC ("ECS1")
	magicECDSAPubP384 = 0x33534345 // BCRYPT_ECDSA_PUBLIC_P384_MAGIC ("ECS3")
	magicECDSAPubP521 = 0x35534345 // BCRYPT_ECDSA_PUBLIC_P521_MAGIC ("ECS5")
)

// RSAPublicBlob encodes an RSA public key as a BCRYPT_RSAPUBLIC_BLOB: a BCRYPT_RSAKEY_BLOB
// header followed by the public exponent and modulus (both big-endian).
func RSAPublicBlob(pub *rsa.PublicKey) []byte {
	exp := big.NewInt(int64(pub.E)).Bytes()
	mod := pub.N.Bytes()

	// BCRYPT_RSAKEY_BLOB: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2 (6 ULONGs).
	const headerLen = 24
	out := make([]byte, headerLen, headerLen+len(exp)+len(mod))
	binary.LittleEndian.PutUint32(out[0:], magicRSAPublic)
	binary.LittleEndian.PutUint32(out[4:], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(out[8:], uint32(len(exp)))
	binary.LittleEndian.PutUint32(out[12:], uint32(len(mod)))
	// cbPrime1 (out[16:]) and cbPrime2 (out[20:]) stay zero for a public key.

	out = append(out, exp...)
	out = append(out, mod...)
	return out
}

// ECCPublicBlob encodes an ECDSA public key as a BCRYPT_ECCPUBLIC_BLOB: a BCRYPT_ECCKEY_BLOB
// header (curve-specific magic + coordinate size) followed by X and Y, each left-padded to
// the coordinate size.
func ECCPublicBlob(pub *ecdsa.PublicKey) ([]byte, error) {
	bits := pub.Curve.Params().BitSize
	var magic uint32
	switch bits {
	case 256:
		magic = magicECDSAPubP256
	case 384:
		magic = magicECDSAPubP384
	case 521:
		magic = magicECDSAPubP521
	default:
		return nil, fmt.Errorf("unsupported EC curve: %d bits", bits)
	}
	cbKey := (bits + 7) / 8

	// BCRYPT_ECCKEY_BLOB: Magic, cbKey (2 ULONGs).
	const headerLen = 8
	out := make([]byte, headerLen, headerLen+2*cbKey)
	binary.LittleEndian.PutUint32(out[0:], magic)
	binary.LittleEndian.PutUint32(out[4:], uint32(cbKey))

	out = append(out, leftPad(pub.X.Bytes(), cbKey)...)
	out = append(out, leftPad(pub.Y.Bytes(), cbKey)...)
	return out, nil
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
