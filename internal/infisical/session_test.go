package infisical

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// selfSignedECDSACertPEM returns a PEM cert whose public key is the given key's public part.
func selfSignedECDSACertPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Acme Corp"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fakeServer stands in for the Infisical API.
func fakeServer(t *testing.T, certPEM string, signHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, loginResponse{AccessToken: "test-token", ExpiresIn: 3600})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, listSignersResponse{Signers: []Signer{
			{ID: "signer-1", Name: "prod-windows", Status: "active", CertificateID: "cert-1", KeyAlgorithm: "ECDSA"},
		}})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/certificate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, signerCertResponse{CertificatePem: certPEM, SignerName: "prod-windows"})
	})
	if signHandler != nil {
		mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/sign", signHandler)
	}
	return httptest.NewServer(mux)
}

func newTestSession(t *testing.T, srv *httptest.Server) *Session {
	t.Helper()
	cfg := &Config{
		ServerURL: srv.URL,
		Auth:      AuthConfig{Method: "universal-auth", ClientID: "id", ClientSecret: "secret"},
	}
	cfg.setDefaults()
	sess, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestSessionFindSignerAndPublicKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := fakeServer(t, selfSignedECDSACertPEM(t, key), nil)
	defer srv.Close()

	sess := newTestSession(t, srv)

	signer, err := sess.FindSigner("prod-windows")
	if err != nil {
		t.Fatalf("FindSigner: %v", err)
	}
	if signer.ID != "signer-1" {
		t.Fatalf("resolved wrong signer: %+v", signer)
	}

	if _, err := sess.FindSigner("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown signer")
	}

	pub, err := sess.PublicKey(signer.ID)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestSessionSign(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wantSig := []byte("a-signature")
	srv := fakeServer(t, selfSignedECDSACertPEM(t, key), func(w http.ResponseWriter, r *http.Request) {
		var body SignParams
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("bad sign body: %v", err)
		}
		if !body.IsDigest {
			t.Error("isDigest should be true")
		}
		if body.SigningAlgorithm != AlgECDSASHA256 {
			t.Errorf("algorithm = %q", body.SigningAlgorithm)
		}
		writeJSON(w, http.StatusOK, signResponse{Signature: base64.StdEncoding.EncodeToString(wantSig)})
	})
	defer srv.Close()

	sess := newTestSession(t, srv)
	got, err := sess.Sign("signer-1", AlgECDSASHA256, []byte("digest-bytes"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(got) != string(wantSig) {
		t.Fatalf("signature = %q, want %q", got, wantSig)
	}
}

// A burst of sign attempts with bad credentials must trigger only one login, so signtool's
// internal retries cannot hammer the server's auth endpoint and trip its lockout.
func TestSessionCachesAuthFailure(t *testing.T) {
	var logins int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logins, 1)
		writeJSON(w, http.StatusUnauthorized, apiErrorBody{Message: "Invalid credentials"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess := newTestSession(t, srv)
	for i := 0; i < 4; i++ {
		if _, err := sess.Sign("signer-1", AlgECDSASHA256, []byte("digest")); err == nil {
			t.Fatal("expected auth failure")
		}
	}
	if n := atomic.LoadInt32(&logins); n != 1 {
		t.Fatalf("expected exactly 1 login attempt (failure cached), got %d", n)
	}
}

func TestSessionSignApprovalRequired(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := fakeServer(t, selfSignedECDSACertPEM(t, key), func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, apiErrorBody{Error: "approval_required", Message: "Signing requires approval."})
	})
	defer srv.Close()

	sess := newTestSession(t, srv)
	_, err := sess.Sign("signer-1", AlgECDSASHA256, []byte("digest"))
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T (%v)", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403, got status %d", apiErr.StatusCode)
	}
}
