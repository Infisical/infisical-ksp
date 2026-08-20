package infisical

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
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
		writeJSON(w, http.StatusForbidden, apiErrorBody{Error: ErrorCodeApprovalRequired, Message: "Signing requires approval."})
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

func TestSessionSignAutoRequestsScopedApproval(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var (
		mu       sync.Mutex
		captured ApprovalRequestParams
		calls    int
	)

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
		writeJSON(w, http.StatusOK, signerCertResponse{CertificatePem: selfSignedECDSACertPEM(t, key), SignerName: "prod-windows"})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/sign", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, apiErrorBody{Error: ErrorCodeApprovalRequired, Message: "Signing requires approval."})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/requests", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		_ = json.NewDecoder(r.Body).Decode(&captured)
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"id": "req-1", "status": "pending"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{
		ServerURL: srv.URL,
		Auth:      AuthConfig{Method: "universal-auth", ClientID: "id", ClientSecret: "secret"},
		Approval:  ApprovalConfig{SigningCount: 3, SigningDuration: "1h"},
	}
	cfg.setDefaults()
	sess, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	digest := []byte("digest")
	_, err = sess.Sign("signer-1", AlgECDSASHA256, digest)
	if err == nil {
		t.Fatal("expected the sign call to fail")
	}

	var opened *ApprovalRequestOpenedError
	if !errors.As(err, &opened) {
		t.Fatalf("expected an ApprovalRequestOpenedError, got %T: %v", err, err)
	}
	if opened.RequestID != "req-1" || opened.Status != "pending" {
		t.Fatalf("expected request req-1/pending, got %q/%q", opened.RequestID, opened.Status)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("the 403 must stay visible through the wrapper, got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected 1 approval request, got %d", calls)
	}
	if captured.RequestedSignings != 3 {
		t.Fatalf("expected 3 requested signings, got %d", captured.RequestedSignings)
	}
	if captured.RequestedWindowDuration != "1h" {
		t.Fatalf("expected the configured window duration, got %q", captured.RequestedWindowDuration)
	}
	want := sha256.Sum256(digest)
	if got := captured.Scope.DataHash; got != hex.EncodeToString(want[:]) {
		t.Fatalf("expected the scope to pin the payload digest, got %q", got)
	}
	if captured.Scope.Hostname == "" {
		t.Fatal("expected the hostname in the scope")
	}
}

func TestSessionSignWithoutApprovalConfigDoesNotRequest(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var requests int32

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/universal-auth/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, loginResponse{AccessToken: "test-token", ExpiresIn: 3600})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/certificate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, signerCertResponse{CertificatePem: selfSignedECDSACertPEM(t, key), SignerName: "prod-windows"})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/sign", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, apiErrorBody{Error: ErrorCodeApprovalRequired, Message: "Signing requires approval."})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/requests", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		writeJSON(w, http.StatusOK, map[string]string{"id": "req-1", "status": "pending"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess := newTestSession(t, srv)
	if _, err := sess.Sign("signer-1", AlgECDSASHA256, []byte("digest")); err == nil {
		t.Fatal("expected the sign call to fail")
	}
	if n := atomic.LoadInt32(&requests); n != 0 {
		t.Fatalf("expected no approval request, got %d", n)
	}
}

func TestSessionSignDoesNotRequestApprovalForARoleDenial(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var requests int32

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
		writeJSON(w, http.StatusOK, signerCertResponse{CertificatePem: selfSignedECDSACertPEM(t, key), SignerName: "prod-windows"})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/sign", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, apiErrorBody{Error: "ForbiddenError", Message: "You are not allowed to sign with this signer."})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/requests", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		writeJSON(w, http.StatusOK, map[string]string{"id": "req-1", "status": "pending"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := &Config{
		ServerURL: srv.URL,
		Auth:      AuthConfig{Method: "universal-auth", ClientID: "id", ClientSecret: "secret"},
		Approval:  ApprovalConfig{SigningCount: 3},
	}
	cfg.setDefaults()
	sess, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}

	digest := []byte("digest")
	_, err = sess.Sign("signer-1", AlgECDSASHA256, digest)
	if err == nil {
		t.Fatal("expected the sign call to fail")
	}
	var opened *ApprovalRequestOpenedError
	if errors.As(err, &opened) {
		t.Fatal("a role denial must not report an opened approval request")
	}
	if n := atomic.LoadInt32(&requests); n != 0 {
		t.Fatalf("expected no approval request, got %d", n)
	}
}

func TestIsApprovalRequired(t *testing.T) {
	cases := []struct {
		name string
		err  *APIError
		want bool
	}{
		{"403 with the approval code", &APIError{StatusCode: 403, Code: ErrorCodeApprovalRequired}, true},
		{"403 role denial", &APIError{StatusCode: 403, Code: "PermissionDenied"}, false},
		{"403 generic forbidden name", &APIError{StatusCode: 403, Code: "ForbiddenError"}, false},
		// An empty code means the body was not an Infisical error, so it is a proxy or WAF denial
		// that opening an approval request cannot resolve.
		{"403 with no code", &APIError{StatusCode: 403, Code: ""}, false},
		{"401 with the approval code", &APIError{StatusCode: 401, Code: ErrorCodeApprovalRequired}, false},
		{"500", &APIError{StatusCode: 500, Code: ""}, false},
	}
	for _, c := range cases {
		if got := c.err.IsApprovalRequired(); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSessionSignReportsAFailedApprovalRequest(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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
		writeJSON(w, http.StatusOK, signerCertResponse{CertificatePem: selfSignedECDSACertPEM(t, key), SignerName: "prod-windows"})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/sign", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, apiErrorBody{Error: ErrorCodeApprovalRequired, Message: "Signing requires approval."})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/requests", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusInternalServerError, apiErrorBody{Error: "InternalServerError", Message: "boom"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	session := newTestSession(t, srv)
	session.cfg.Approval = ApprovalConfig{SigningCount: 5}
	_, err := session.Sign("signer-1", AlgECDSASHA256, []byte("digest"))
	if err == nil {
		t.Fatal("expected the sign call to fail")
	}

	var failed *ApprovalRequestFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("expected an ApprovalRequestFailedError, got %T: %v", err, err)
	}
	// The original 403 has to stay reachable so the provider still maps to an access-denied status.
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("the 403 must stay visible through the wrapper, got %v", err)
	}
	if failed.RequestErr == nil {
		t.Fatal("expected the approval-request failure to be recorded")
	}
}

func TestSessionSignSendsClientMetadataOnTheWire(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var (
		mu   sync.Mutex
		body map[string]any
	)

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
		writeJSON(w, http.StatusOK, signerCertResponse{CertificatePem: selfSignedECDSACertPEM(t, key), SignerName: "prod-windows"})
	})
	mux.HandleFunc("/api/v1/cert-manager/signers/signer-1/sign", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Unlock()
		writeJSON(w, http.StatusOK, signResponse{Signature: base64.StdEncoding.EncodeToString([]byte("sig"))})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	session := newTestSession(t, srv)
	if _, err := session.Sign("signer-1", AlgECDSASHA256, []byte("digest")); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	metadata, ok := body["clientMetadata"].(map[string]any)
	if !ok {
		t.Fatalf("the sign call must carry clientMetadata, got %v", body)
	}
	ctx := CurrentSigningContext()
	if metadata["hostname"] != ctx.Hostname {
		t.Errorf("hostname on the wire = %v, want %q", metadata["hostname"], ctx.Hostname)
	}
	if metadata["tool"] != ctx.Application {
		t.Errorf("tool on the wire = %v, want %q", metadata["tool"], ctx.Application)
	}
}
