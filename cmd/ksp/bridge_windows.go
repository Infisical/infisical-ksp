//go:build windows

// bridge_windows.go holds the //export Go functions that bridge_windows.c calls through the CNG
// function table. It marshals between the C ABI and the internal packages. cgo, Windows-only.
package main

/*
#cgo windows LDFLAGS: -lncrypt -lbcrypt -lcrypt32
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/Infisical/infisical-ksp/internal/cng"
	"golang.org/x/sys/windows"
)

// BCRYPT padding flags (from bcrypt.h), mirrored so the Go side can read dwFlags.
const (
	bcryptPadPKCS1 = 0x00000002
	bcryptPadPSS   = 0x00000008
)

func main() {} // required for -buildmode=c-shared;

// utf16PtrToString reads a Windows wide string (LPCWSTR) passed from C.
func utf16PtrToString(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(p))
}

// cBytes copies a Go byte slice into a C heap buffer the C side must free(). Returns the
// pointer and length; on empty input returns (nil, 0).
func cBytes(b []byte) (unsafe.Pointer, C.int) {
	if len(b) == 0 {
		return nil, 0
	}
	return C.CBytes(b), C.int(len(b))
}

//export GoOpenProvider
func GoOpenProvider() (C.uintptr_t, C.uint) {
	h, err := openProvider()
	if err != nil {
		logError("OpenProvider", err)
		return 0, C.uint(statusFromError(err))
	}
	return C.uintptr_t(h), C.uint(statusSuccess)
}

//export GoOpenKey
func GoOpenKey(prov C.uintptr_t, name unsafe.Pointer) (C.uintptr_t, C.uint) {
	keyName := utf16PtrToString(name)
	h, err := openKey(uintptr(prov), keyName)
	if err != nil {
		logError("OpenKey("+keyName+")", err)
		return 0, C.uint(statusFromError(err))
	}
	return C.uintptr_t(h), C.uint(statusSuccess)
}

//export GoFreeHandle
func GoFreeHandle(h C.uintptr_t) {
	freeHandle(uintptr(h))
}

// GoSignatureMaxSize returns the signature size for the key (RSA: modulus bytes; ECDSA:
// 2*coordinate), for SignHash's sizing call.
//
//export GoSignatureMaxSize
func GoSignatureMaxSize(key C.uintptr_t) (C.uint, C.uint) {
	ks, err := keyByHandle(uintptr(key))
	if err != nil {
		return 0, C.uint(statusInvalidParameter)
	}
	bits := ks.keyLengthBits()
	size := (bits + 7) / 8
	if ks.keyType == cng.KeyECDSA {
		size *= 2
	}
	return C.uint(size), C.uint(statusSuccess)
}

// GoSignHash signs the digest. pPaddingInfo points at a BCRYPT_*_PADDING_INFO whose first field
// is the hash id (LPCWSTR); for ECDSA it is nil and the hash is inferred from the digest length.
// Returns a C-heap buffer the caller frees.
//
//export GoSignHash
func GoSignHash(key C.uintptr_t, dwFlags C.uint, pPaddingInfo unsafe.Pointer, pbInput *C.uchar, cbInput C.uint) (unsafe.Pointer, C.int, C.uint) {
	ks, err := keyByHandle(uintptr(key))
	if err != nil {
		return nil, 0, C.uint(statusInvalidParameter)
	}
	digest := C.GoBytes(unsafe.Pointer(pbInput), C.int(cbInput))

	var padding cng.Padding
	var hashName string
	switch {
	case uint32(dwFlags)&bcryptPadPKCS1 != 0:
		padding = cng.PaddingPKCS1
		hashName = readPaddingHashID(pPaddingInfo)
	case uint32(dwFlags)&bcryptPadPSS != 0:
		padding = cng.PaddingPSS
		hashName = readPaddingHashID(pPaddingInfo)
	default: // ECDSA: no padding info, hash inferred from digest length.
		padding = cng.PaddingNone
		h, herr := cng.HashFromDigestLen(len(digest))
		if herr != nil {
			logError("SignHash", herr)
			return nil, 0, C.uint(statusInvalidParameter)
		}
		hashName = h
	}

	sig, err := signHash(ks, padding, hashName, digest)
	if err != nil {
		logError("SignHash", err)
		return nil, 0, C.uint(statusFromError(err))
	}
	ptr, n := cBytes(sig)
	return ptr, n, C.uint(statusSuccess)
}

// readPaddingHashID reads the pszAlgId (first pointer-sized field, an LPCWSTR) shared by
// BCRYPT_PKCS1_PADDING_INFO and BCRYPT_PSS_PADDING_INFO.
func readPaddingHashID(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	algIDPtr := *(*unsafe.Pointer)(p)
	return utf16PtrToString(algIDPtr)
}

// GoExportKey returns the public key encoded as a CNG public blob.
//
//export GoExportKey
func GoExportKey(key C.uintptr_t) (unsafe.Pointer, C.int, C.uint) {
	ks, err := keyByHandle(uintptr(key))
	if err != nil {
		return nil, 0, C.uint(statusInvalidParameter)
	}
	blob, err := exportPublicBlob(ks)
	if err != nil {
		logError("ExportKey", err)
		return nil, 0, C.uint(statusFromError(err))
	}
	ptr, n := cBytes(blob)
	return ptr, n, C.uint(statusSuccess)
}

// GoGetKeyProperty answers the metadata queries signtool/CNG make about a key. Unknown
// properties return NTE_NOT_SUPPORTED so CNG can fall back to defaults.
//
//export GoGetKeyProperty
func GoGetKeyProperty(key C.uintptr_t, prop unsafe.Pointer) (unsafe.Pointer, C.int, C.uint) {
	ks, err := keyByHandle(uintptr(key))
	if err != nil {
		return nil, 0, C.uint(statusInvalidParameter)
	}
	value, ok := keyProperty(ks, utf16PtrToString(prop))
	if !ok {
		return nil, 0, C.uint(statusNotSupported)
	}
	ptr, n := cBytes(value)
	return ptr, n, C.uint(statusSuccess)
}
