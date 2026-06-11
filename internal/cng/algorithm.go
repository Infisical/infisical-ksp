// Package cng translates between Windows CNG and Infisical: it maps a sign request to an Infisical
// signing algorithm, reshapes ECDSA signatures, and encodes public keys as CNG blobs. OS-agnostic.
package cng

import (
	"fmt"
	"strings"

	"github.com/Infisical/infisical-ksp/internal/infisical"
)

// KeyType is the key family a Signer uses.
type KeyType int

const (
	KeyRSA KeyType = iota
	KeyECDSA
)

// Padding is the RSA padding CNG asked for. ECDSA has no padding.
type Padding int

const (
	PaddingNone Padding = iota // ECDSA
	PaddingPKCS1
	PaddingPSS
)

// Algorithm maps a CNG sign request (key family, padding, hash) to the Infisical signing
// algorithm string. hash is the CNG hash identifier, e.g. "SHA256" (case-insensitive).
func Algorithm(key KeyType, padding Padding, hash string) (string, error) {
	h := strings.ToUpper(strings.TrimSpace(hash))
	switch key {
	case KeyRSA:
		switch padding {
		case PaddingPKCS1:
			switch h {
			case "SHA256":
				return infisical.AlgRSAPKCS1SHA256, nil
			case "SHA384":
				return infisical.AlgRSAPKCS1SHA384, nil
			case "SHA512":
				return infisical.AlgRSAPKCS1SHA512, nil
			}
		case PaddingPSS:
			switch h {
			case "SHA256":
				return infisical.AlgRSAPSSSHA256, nil
			case "SHA384":
				return infisical.AlgRSAPSSSHA384, nil
			case "SHA512":
				return infisical.AlgRSAPSSSHA512, nil
			}
		default:
			return "", fmt.Errorf("RSA signing requires PKCS1 or PSS padding")
		}
		return "", fmt.Errorf("unsupported RSA hash %q", hash)
	case KeyECDSA:
		switch h {
		case "SHA256":
			return infisical.AlgECDSASHA256, nil
		case "SHA384":
			return infisical.AlgECDSASHA384, nil
		case "SHA512":
			return infisical.AlgECDSASHA512, nil
		}
		return "", fmt.Errorf("unsupported ECDSA hash %q", hash)
	default:
		return "", fmt.Errorf("unsupported key type")
	}
}

// HashFromDigestLen infers the hash name from a digest length. ECDSA sign requests carry no
// padding-info struct, so the hash is recovered from the digest length signtool provides.
func HashFromDigestLen(n int) (string, error) {
	switch n {
	case 32:
		return "SHA256", nil
	case 48:
		return "SHA384", nil
	case 64:
		return "SHA512", nil
	default:
		return "", fmt.Errorf("unexpected digest length %d (want 32, 48, or 64)", n)
	}
}
