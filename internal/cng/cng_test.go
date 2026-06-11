package cng

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/Infisical/infisical-ksp/internal/infisical"
)

func TestAlgorithm(t *testing.T) {
	cases := []struct {
		key     KeyType
		padding Padding
		hash    string
		want    string
	}{
		{KeyRSA, PaddingPKCS1, "SHA256", infisical.AlgRSAPKCS1SHA256},
		{KeyRSA, PaddingPKCS1, "sha384", infisical.AlgRSAPKCS1SHA384},
		{KeyRSA, PaddingPKCS1, "SHA512", infisical.AlgRSAPKCS1SHA512},
		{KeyRSA, PaddingPSS, "SHA256", infisical.AlgRSAPSSSHA256},
		{KeyRSA, PaddingPSS, "SHA384", infisical.AlgRSAPSSSHA384},
		{KeyRSA, PaddingPSS, "SHA512", infisical.AlgRSAPSSSHA512},
		{KeyECDSA, PaddingNone, "SHA256", infisical.AlgECDSASHA256},
		{KeyECDSA, PaddingNone, "SHA384", infisical.AlgECDSASHA384},
		{KeyECDSA, PaddingNone, "SHA512", infisical.AlgECDSASHA512},
	}
	for _, c := range cases {
		got, err := Algorithm(c.key, c.padding, c.hash)
		if err != nil {
			t.Errorf("Algorithm(%v,%v,%q) error: %v", c.key, c.padding, c.hash, err)
			continue
		}
		if got != c.want {
			t.Errorf("Algorithm(%v,%v,%q) = %q, want %q", c.key, c.padding, c.hash, got, c.want)
		}
	}
}

func TestAlgorithmErrors(t *testing.T) {
	if _, err := Algorithm(KeyRSA, PaddingPKCS1, "MD5"); err == nil {
		t.Error("expected error for unsupported RSA hash")
	}
	if _, err := Algorithm(KeyRSA, PaddingNone, "SHA256"); err == nil {
		t.Error("expected error for RSA with no padding")
	}
	if _, err := Algorithm(KeyECDSA, PaddingNone, "SHA1"); err == nil {
		t.Error("expected error for unsupported ECDSA hash")
	}
}

func TestHashFromDigestLen(t *testing.T) {
	for n, want := range map[int]string{32: "SHA256", 48: "SHA384", 64: "SHA512"} {
		got, err := HashFromDigestLen(n)
		if err != nil || got != want {
			t.Errorf("HashFromDigestLen(%d) = %q,%v; want %q", n, got, err, want)
		}
	}
	if _, err := HashFromDigestLen(20); err == nil {
		t.Error("expected error for digest length 20")
	}
}

func TestECDSADERToRawRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		bits := curve.Params().BitSize
		size := (bits + 7) / 8
		digest := sha256.Sum256([]byte("payload"))

		der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ECDSADERToRaw(der, bits)
		if err != nil {
			t.Fatalf("ECDSADERToRaw: %v", err)
		}
		if len(raw) != 2*size {
			t.Fatalf("raw length = %d, want %d", len(raw), 2*size)
		}
		r := new(big.Int).SetBytes(raw[:size])
		s := new(big.Int).SetBytes(raw[size:])
		if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
			t.Errorf("reconstructed r,s did not verify for %d-bit curve", bits)
		}
	}
}

func TestECDSADERToRawRejectsTrailingBytes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256([]byte("x"))
	der, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if _, err := ECDSADERToRaw(append(der, 0x00), 256); err == nil {
		t.Error("expected error for trailing bytes")
	}
}

func TestRSAPublicBlob(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	blob := RSAPublicBlob(&key.PublicKey)

	if got := binary.LittleEndian.Uint32(blob[0:]); got != magicRSAPublic {
		t.Errorf("magic = %#x, want %#x", got, magicRSAPublic)
	}
	if got := binary.LittleEndian.Uint32(blob[4:]); got != uint32(key.N.BitLen()) {
		t.Errorf("bitlength = %d, want %d", got, key.N.BitLen())
	}
	cbExp := binary.LittleEndian.Uint32(blob[8:])
	cbMod := binary.LittleEndian.Uint32(blob[12:])
	wantExp := big.NewInt(int64(key.E)).Bytes()
	wantMod := key.N.Bytes()
	if int(cbExp) != len(wantExp) || int(cbMod) != len(wantMod) {
		t.Fatalf("cbExp=%d cbMod=%d, want %d %d", cbExp, cbMod, len(wantExp), len(wantMod))
	}
	exp := blob[24 : 24+cbExp]
	mod := blob[24+cbExp : 24+cbExp+cbMod]
	if !bytes.Equal(exp, wantExp) || !bytes.Equal(mod, wantMod) {
		t.Error("exponent or modulus bytes do not match")
	}
}

func TestECCPublicBlob(t *testing.T) {
	cases := []struct {
		curve elliptic.Curve
		magic uint32
		cbKey int
	}{
		{elliptic.P256(), magicECDSAPubP256, 32},
		{elliptic.P384(), magicECDSAPubP384, 48},
		{elliptic.P521(), magicECDSAPubP521, 66},
	}
	for _, c := range cases {
		key, _ := ecdsa.GenerateKey(c.curve, rand.Reader)
		blob, err := ECCPublicBlob(&key.PublicKey)
		if err != nil {
			t.Fatalf("ECCPublicBlob: %v", err)
		}
		if got := binary.LittleEndian.Uint32(blob[0:]); got != c.magic {
			t.Errorf("magic = %#x, want %#x", got, c.magic)
		}
		if got := binary.LittleEndian.Uint32(blob[4:]); int(got) != c.cbKey {
			t.Errorf("cbKey = %d, want %d", got, c.cbKey)
		}
		if len(blob) != 8+2*c.cbKey {
			t.Errorf("blob length = %d, want %d", len(blob), 8+2*c.cbKey)
		}
		x := new(big.Int).SetBytes(blob[8 : 8+c.cbKey])
		y := new(big.Int).SetBytes(blob[8+c.cbKey:])
		if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
			t.Error("X or Y coordinate mismatch")
		}
	}
}
