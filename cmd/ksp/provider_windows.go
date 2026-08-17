//go:build windows

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"

	"github.com/Infisical/infisical-ksp/internal/cng"
	"github.com/Infisical/infisical-ksp/internal/infisical"
)

// SECURITY_STATUS values returned to CNG (from winerror.h). 0 is success.
const (
	statusSuccess          uint32 = 0x00000000
	statusNotSupported     uint32 = 0x80090029 // NTE_NOT_SUPPORTED
	statusPerm             uint32 = 0x80090010 // NTE_PERM (access denied)
	statusBadKeyset        uint32 = 0x80090016 // NTE_BAD_KEYSET
	statusInvalidParameter uint32 = 0x80090027 // NTE_INVALID_PARAMETER
	statusFail             uint32 = 0x80090020 // NTE_FAIL
)

// providerState is created per OpenProvider call and holds the Infisical session.
type providerState struct {
	session *infisical.Session
}

// keyState is created per OpenKey call. It binds a CNG key handle to a Signer and caches the
// public key so property/export queries do not re-fetch.
type keyState struct {
	prov      *providerState
	signer    infisical.Signer
	pub       crypto.PublicKey
	keyType   cng.KeyType
	curveBits int // ECDSA only
}

// handle registry: CNG references objects through opaque integer handles. A Go pointer cannot
// cross into C between calls, so objects are stored here and C receives the integer key.
var (
	handleMu   sync.Mutex
	handles            = map[uintptr]any{}
	nextHandle uintptr = 1
)

func registerHandle(v any) uintptr {
	handleMu.Lock()
	defer handleMu.Unlock()
	h := nextHandle
	nextHandle++
	handles[h] = v
	return h
}

func lookupHandle(h uintptr) any {
	handleMu.Lock()
	defer handleMu.Unlock()
	return handles[h]
}

func freeHandle(h uintptr) {
	handleMu.Lock()
	defer handleMu.Unlock()
	delete(handles, h)
}

// openProvider loads config, builds an Infisical session, and returns a provider handle.
func openProvider() (uintptr, error) {
	cfg, err := infisical.LoadConfig()
	if err != nil {
		// The configured log path is unknown when config loading fails, so log to the default path.
		setupLogging(infisical.DefaultLogPath())
		return 0, err
	}
	setupLogging(cfg.LogFile)
	session, err := infisical.NewSession(cfg)
	if err != nil {
		return 0, err
	}
	return registerHandle(&providerState{session: session}), nil
}

// openKey resolves the Signer named by /kc, fetches its public key, and returns a key handle.
func openKey(provHandle uintptr, name string) (uintptr, error) {
	prov, ok := lookupHandle(provHandle).(*providerState)
	if !ok {
		return 0, errBadHandle
	}
	signer, err := prov.session.FindSigner(name)
	if err != nil {
		return 0, err
	}
	pub, err := prov.session.PublicKey(signer.ID)
	if err != nil {
		return 0, err
	}

	ks := &keyState{prov: prov, signer: signer, pub: pub}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		ks.keyType = cng.KeyRSA
	case *ecdsa.PublicKey:
		ks.keyType = cng.KeyECDSA
		ks.curveBits = p.Curve.Params().BitSize
	default:
		return 0, fmt.Errorf("unsupported key type %T", pub)
	}
	return registerHandle(ks), nil
}

func keyByHandle(h uintptr) (*keyState, error) {
	ks, ok := lookupHandle(h).(*keyState)
	if !ok {
		return nil, errBadHandle
	}
	return ks, nil
}

// exportPublicBlob encodes the public key as the CNG blob for its key type.
func exportPublicBlob(ks *keyState) ([]byte, error) {
	switch pub := ks.pub.(type) {
	case *rsa.PublicKey:
		return cng.RSAPublicBlob(pub), nil
	case *ecdsa.PublicKey:
		return cng.ECCPublicBlob(pub)
	default:
		return nil, fmt.Errorf("unsupported key type %T", ks.pub)
	}
}

// signHash maps the CNG request to an Infisical signing algorithm, signs remotely, and (for
// ECDSA) reshapes the DER signature into the raw r||s form CNG expects.
func signHash(ks *keyState, padding cng.Padding, hashName string, digest []byte) ([]byte, error) {
	algorithm, err := cng.Algorithm(ks.keyType, padding, hashName)
	if err != nil {
		return nil, err
	}
	sig, err := ks.prov.session.Sign(ks.signer.ID, algorithm, digest)
	if err != nil {
		return nil, err
	}
	if ks.keyType == cng.KeyECDSA {
		return cng.ECDSADERToRaw(sig, ks.curveBits)
	}
	return sig, nil
}

// keyLengthBits reports the key size CNG asks for via NCRYPT_LENGTH_PROPERTY.
func (ks *keyState) keyLengthBits() int {
	switch pub := ks.pub.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	default:
		return 0
	}
}

// algorithmGroup is the value of NCRYPT_ALGORITHM_GROUP_PROPERTY ("RSA" or "ECDSA").
func (ks *keyState) algorithmGroup() string {
	if ks.keyType == cng.KeyRSA {
		return "RSA"
	}
	return "ECDSA"
}

var errBadHandle = errors.New("invalid handle")

// statusFromError maps an engine error to the CNG SECURITY_STATUS returned to the host.
func statusFromError(err error) uint32 {
	if err == nil {
		return statusSuccess
	}
	if errors.Is(err, errBadHandle) {
		return statusInvalidParameter
	}

	var apiErr *infisical.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == 403: // approval required or insufficient role
			return statusPerm
		case apiErr.StatusCode == 401:
			return statusPerm
		case apiErr.StatusCode == 404:
			return statusBadKeyset
		case apiErr.StatusCode == 400:
			return statusInvalidParameter
		default:
			return statusFail
		}
	}
	// Transport failures and everything else.
	return statusFail
}

// adviceForError returns a short fix-it hint for common failures, or "" when none applies.
func adviceForError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, errBadHandle) {
		return "internal handle error; this usually indicates a host or provider-state bug, not a configuration problem"
	}

	var opened *infisical.ApprovalRequestOpenedError
	if errors.As(err, &opened) {
		return fmt.Sprintf("signing needs approved access, so approval request %s was opened (%s). Ask an "+
			"approver to review it under Cert Manager > Code Signing > Signers > Approvals, then run the same "+
			"command again", opened.RequestID, opened.Status)
	}

	var pending *infisical.ApprovalRequestPendingError
	if errors.As(err, &pending) {
		return "signing needs approved access and your approval request is already awaiting review. Ask an " +
			"approver to review it under Cert Manager > Code Signing > Signers > Approvals, then run the same " +
			"command again"
	}

	var notConfigured *infisical.ApprovalNotConfiguredError
	if errors.As(err, &notConfigured) {
		return "signing needs approved access, and this KSP has no approval block configured, so it did not " +
			"open a request. Ask an approver for access under Cert Manager > Code Signing > Signers > " +
			"Approvals, or set approval.signing_count and approval.signing_duration in the KSP config so " +
			"requests are opened for you (https://infisical.com/docs/documentation/platform/pki/code-signing/approvals)"
	}

	var requestFailed *infisical.ApprovalRequestFailedError
	if errors.As(err, &requestFailed) {
		return fmt.Sprintf("signing needs approved access, and opening an approval request failed (%v). Check "+
			"that the identity may request signing access and that the server is reachable, then run the same "+
			"command again", requestFailed.RequestErr)
	}

	var apiErr *infisical.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == 403:
			// A 403 is approval-required or a role denial;
			return "signing was denied (HTTP 403): this identity needs an approved access request " +
				"(Cert Manager > Code Signing > Signers > Approvals), or it must be a Signer member " +
				"with the Administrator or Operator role (Auditors cannot sign). Resolve access, then " +
				"run the same command again"
		case apiErr.StatusCode == 401:
			return "authentication failed: check INFISICAL_UNIVERSAL_AUTH_CLIENT_ID and " +
				"INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET, and confirm the identity is a member of the Signer"
		case apiErr.StatusCode == 404:
			return "not found: the Signer or its certificate does not exist, or is not visible to this identity"
		case apiErr.StatusCode == 400:
			return "the server rejected the request: verify the key type and signing algorithm are supported"
		case apiErr.StatusCode >= 500:
			return "the Infisical server reported an internal error; retry shortly"
		}
		return ""
	}

	var reqErr *infisical.RequestError
	if errors.As(err, &reqErr) {
		return "cannot reach Infisical: check server_url, network connectivity, and TLS " +
			"(for a self-hosted instance with a private CA, set tls.ca_cert_path in the config)"
	}
	return ""
}
