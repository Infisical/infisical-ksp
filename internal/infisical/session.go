package infisical

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tokenSafetyMargin is subtracted from a token's reported lifetime so re-authentication happens
// before it actually expires mid-request.
const tokenSafetyMargin = 30 * time.Second

// authFailureCacheTTL briefly caches a login failure. signtool opens a fresh provider (a new
// Session) per key-open retry, so without a process-wide cache one bad-credential attempt becomes
// several failed logins and can trip the server's auth lockout.
const authFailureCacheTTL = 10 * time.Second

type authFailure struct {
	err   error
	until time.Time
}

var (
	authFailMu    sync.Mutex
	authFailCache = map[string]authFailure{}
)

func cachedAuthFailure(key string) error {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	if f, ok := authFailCache[key]; ok {
		if time.Now().Before(f.until) {
			return f.err
		}
		delete(authFailCache, key)
	}
	return nil
}

func recordAuthFailure(key string, err error) {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	authFailCache[key] = authFailure{err: err, until: time.Now().Add(authFailureCacheTTL)}
}

func clearAuthFailure(key string) {
	authFailMu.Lock()
	defer authFailMu.Unlock()
	delete(authFailCache, key)
}

// Session is the stateful object the KSP holds for the lifetime of an open provider. It owns
// the access token and small in-memory caches, and is safe for concurrent use. One Session
// backs many key handles.
type Session struct {
	cfg    *Config
	client *Client

	mu sync.Mutex

	token       string
	tokenExpiry time.Time

	signers       []Signer
	signersExpiry time.Time

	pubKeys map[string]pubKeyCacheEntry // keyed by signer ID
}

type pubKeyCacheEntry struct {
	key       crypto.PublicKey
	expiresAt time.Time
}

// NewSession builds a Session from config. It does not contact the network yet.
func NewSession(cfg *Config) (*Session, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Session{cfg: cfg, client: client, pubKeys: map[string]pubKeyCacheEntry{}}, nil
}

// ensureToken returns a valid access token, logging in (or re-logging in) if needed.
// Callers must hold s.mu.
func (s *Session) ensureToken() (string, error) {
	// Token auth uses the configured access token directly and does not refresh it.
	if s.cfg.Auth.Method == AuthMethodToken {
		if s.cfg.Auth.Token == "" {
			return "", fmt.Errorf("token auth selected but no token: set %s", EnvToken)
		}
		return s.cfg.Auth.Token, nil
	}
	if s.token != "" && time.Now().Before(s.tokenExpiry) {
		return s.token, nil
	}
	// Return a recently-cached failure without re-logging in (see authFailureCacheTTL).
	key := s.cfg.Auth.ClientID + "@" + s.cfg.ServerURL
	if err := cachedAuthFailure(key); err != nil {
		return "", err
	}
	if s.cfg.Auth.ClientID == "" || s.cfg.Auth.ClientSecret == "" {
		err := fmt.Errorf("no Universal Auth credentials: set %s and %s", EnvClientID, EnvClientSecret)
		recordAuthFailure(key, err)
		return "", err
	}
	token, ttl, err := s.client.Login(s.cfg.Auth.ClientID, s.cfg.Auth.ClientSecret)
	if err != nil {
		recordAuthFailure(key, err)
		return "", err
	}
	s.token = token
	s.tokenExpiry = cacheExpiry(ttl, s.cfg.Cache.TokenTTLSeconds)
	clearAuthFailure(key)
	return token, nil
}

// cacheExpiry picks the earlier of the server-reported lifetime and the configured ceiling,
// minus a safety margin.
func cacheExpiry(reported time.Duration, ceilingSeconds int) time.Time {
	ttl := reported
	if ceiling := time.Duration(ceilingSeconds) * time.Second; ceiling > 0 && ceiling < ttl {
		ttl = ceiling
	}
	ttl -= tokenSafetyMargin
	if ttl < tokenSafetyMargin {
		ttl = tokenSafetyMargin
	}
	return time.Now().Add(ttl)
}

// Signers returns the available Signers, cached for the configured TTL.
func (s *Session) Signers() ([]Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.signers != nil && time.Now().Before(s.signersExpiry) {
		return s.signers, nil
	}
	token, err := s.ensureToken()
	if err != nil {
		return nil, err
	}
	signers, err := s.client.ListSigners(token)
	if err != nil {
		return nil, err
	}
	s.signers = signers
	s.signersExpiry = time.Now().Add(time.Duration(s.cfg.Cache.SignerTTLSeconds) * time.Second)
	return signers, nil
}

// FindSigner resolves a Signer by name or by ID (the value passed to signtool's /kc).
func (s *Session) FindSigner(nameOrID string) (Signer, error) {
	signers, err := s.Signers()
	if err != nil {
		return Signer{}, err
	}
	for _, sg := range signers {
		if sg.Name == nameOrID || sg.ID == nameOrID {
			return sg, nil
		}
	}
	return Signer{}, fmt.Errorf("no signer named %q is available to this identity", nameOrID)
}

// PublicKey returns a Signer's public key, parsed from its certificate and cached.
func (s *Session) PublicKey(signerID string) (crypto.PublicKey, error) {
	s.mu.Lock()
	if entry, ok := s.pubKeys[signerID]; ok && time.Now().Before(entry.expiresAt) {
		s.mu.Unlock()
		return entry.key, nil
	}
	token, err := s.ensureToken()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	certPEM, err := s.client.GetCertificate(token, signerID)
	if err != nil {
		return nil, err
	}
	key, err := publicKeyFromCertPEM(certPEM)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.pubKeys[signerID] = pubKeyCacheEntry{
		key:       key,
		expiresAt: time.Now().Add(time.Duration(s.cfg.Cache.CertTTLSeconds) * time.Second),
	}
	s.mu.Unlock()
	return key, nil
}

// Sign sends a base64-encoded digest to Infisical and returns the raw signature bytes.
func (s *Session) Sign(signerID, algorithm string, digest []byte) ([]byte, error) {
	s.mu.Lock()
	token, err := s.ensureToken()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	signCtx := CurrentSigningContext()
	sigB64, err := s.client.Sign(token, signerID, SignParams{
		DataB64:          base64.StdEncoding.EncodeToString(digest),
		SigningAlgorithm: algorithm,
		IsDigest:         true,
		ClientMetadata:   signCtx.ClientMetadata(),
	})
	if err != nil {
		return nil, s.autoRequestOnDenial(token, signerID, signCtx, digest, err)
	}
	return base64.StdEncoding.DecodeString(sigB64)
}

func (s *Session) autoRequestOnDenial(
	token, signerID string,
	signCtx SigningContext,
	digest []byte,
	signErr error,
) error {
	var apiErr *APIError
	if !errors.As(signErr, &apiErr) || !apiErr.IsApprovalRequired() {
		return signErr
	}

	payloadDigest := sha256.Sum256(digest)
	id, status, err := s.requestApprovalIfConfigured(token, signerID, signCtx, hex.EncodeToString(payloadDigest[:]))
	switch {
	case err != nil:
		return &ApprovalRequestFailedError{Err: signErr, RequestErr: err}
	case id != "":
		return &ApprovalRequestOpenedError{Err: signErr, RequestID: id, Status: status}
	default:
		return signErr // no approval block configured, so nothing was opened
	}
}

func (s *Session) requestApprovalIfConfigured(
	token, signerID string,
	signCtx SigningContext,
	dataHash string,
) (id, status string, err error) {
	cfg := s.cfg.Approval
	if cfg.SigningCount == 0 && cfg.SigningDuration == "" {
		return "", "", nil
	}

	params := ApprovalRequestParams{
		Justification: approvalJustification(signCtx.Hostname),
		Scope:         signCtx.RequestScope(dataHash),
	}
	if cfg.SigningCount > 0 {
		params.RequestedSignings = cfg.SigningCount
	}
	if cfg.SigningDuration != "" {
		window, parseErr := parseApprovalDuration(cfg.SigningDuration)
		if parseErr != nil {
			return "", "", fmt.Errorf("invalid approval.signing_duration %q: %w", cfg.SigningDuration, parseErr)
		}
		now := time.Now().UTC()
		params.RequestedWindowStart = now.Format(time.RFC3339)
		params.RequestedWindowEnd = now.Add(window).Format(time.RFC3339)
	}

	return s.client.RequestApproval(token, signerID, params)
}

func parseApprovalDuration(duration string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(duration, "d"); ok {
		count, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid duration: %s", duration)
		}
		return time.Duration(count) * 24 * time.Hour, nil
	}
	return time.ParseDuration(duration)
}

func approvalJustification(hostname string) string {
	if hostname == "" {
		return "Auto-requested by the Infisical KSP"
	}
	return fmt.Sprintf("Auto-requested by the Infisical KSP on %s", hostname)
}

func publicKeyFromCertPEM(certPEM string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certPEM)))
	if block == nil {
		return nil, fmt.Errorf("certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert.PublicKey, nil
}
