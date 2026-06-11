//go:build windows

package main

import (
	"encoding/binary"

	"golang.org/x/sys/windows"
)

// CNG key property identifiers (the LPCWSTR names from ncrypt.h) that signtool/CNG query.
const (
	propAlgorithmGroup = "Algorithm Group" // NCRYPT_ALGORITHM_GROUP_PROPERTY
	propAlgorithmName  = "Algorithm Name"  // NCRYPT_ALGORITHM_PROPERTY
	propLength         = "Length"          // NCRYPT_LENGTH_PROPERTY (bits)
	propExportPolicy   = "Export Policy"   // NCRYPT_EXPORT_POLICY_PROPERTY
	propKeyUsage       = "Key Usage"       // NCRYPT_KEY_USAGE_PROPERTY
)

const ncryptAllowSigningFlag = 0x00000001

// keyProperty returns a CNG key property's bytes, or ok=false if unsupported. String properties
// are null-terminated UTF-16; numeric ones are a little-endian DWORD.
func keyProperty(ks *keyState, name string) ([]byte, bool) {
	switch name {
	case propAlgorithmGroup:
		return utf16z(ks.algorithmGroup()), true
	case propAlgorithmName:
		return utf16z(algorithmName(ks)), true
	case propLength:
		return dwordLE(uint32(ks.keyLengthBits())), true
	case propExportPolicy:
		return dwordLE(0), true // not exportable
	case propKeyUsage:
		return dwordLE(ncryptAllowSigningFlag), true
	default:
		return nil, false
	}
}

// algorithmName is the NCRYPT_ALGORITHM_PROPERTY value: "RSA", or the curve-specific ECDSA id.
func algorithmName(ks *keyState) string {
	if ks.algorithmGroup() == "RSA" {
		return "RSA"
	}
	switch ks.curveBits {
	case 256:
		return "ECDSA_P256"
	case 384:
		return "ECDSA_P384"
	case 521:
		return "ECDSA_P521"
	default:
		return "ECDSA"
	}
}

func utf16z(s string) []byte {
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return nil
	}
	buf := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(buf[i*2:], v)
	}
	return buf
}

func dwordLE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
