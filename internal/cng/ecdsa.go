package cng

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ecdsaDERSig is the ASN.1 structure Infisical returns for ECDSA signatures.
type ecdsaDERSig struct {
	R *big.Int
	S *big.Int
}

// ECDSADERToRaw converts a DER-encoded ECDSA signature (SEQUENCE { r, s }) into the raw
// fixed-size r||s form CNG expects: each of r and s left-padded to the curve's byte size.
// curveBits is the curve order size (256, 384, 521).
func ECDSADERToRaw(der []byte, curveBits int) ([]byte, error) {
	var sig ecdsaDERSig
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("parse DER ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing bytes after DER ECDSA signature")
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, fmt.Errorf("ECDSA signature has non-positive r or s")
	}

	size := (curveBits + 7) / 8
	r := sig.R.Bytes()
	s := sig.S.Bytes()
	if len(r) > size || len(s) > size {
		return nil, fmt.Errorf("ECDSA r/s larger than curve size %d", size)
	}

	out := make([]byte, 2*size)
	copy(out[size-len(r):size], r)
	copy(out[2*size-len(s):], s)
	return out, nil
}
