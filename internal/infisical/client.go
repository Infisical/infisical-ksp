package infisical

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	userAgent     = "infisical-ksp"
	clientTimeout = 30 * time.Second
)

// Signer is one signing identity in Infisical. It maps to one CNG key.
type Signer struct {
	ID               string  `json:"id"`
	Name             string  `json:"name"`
	Status           string  `json:"status"`
	CertificateID    string  `json:"certificateId"`
	KeyAlgorithm     string  `json:"keyAlgorithm"`
	ApprovalPolicyID *string `json:"approvalPolicyId"`
}

// Client talks to the Infisical REST API. It is safe for concurrent use.
type Client struct {
	http *resty.Client
}

// NewClient builds a client from config, wiring TLS for self-hosted instances.
func NewClient(cfg *Config) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLS.SkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if cfg.TLS.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.TLS.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", cfg.TLS.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	http := resty.New().
		SetBaseURL(strings.TrimRight(cfg.ServerURL, "/")).
		SetTLSClientConfig(tlsCfg).
		SetTimeout(clientTimeout).
		SetHeader("User-Agent", userAgent)

	return &Client{http: http}, nil
}

type loginRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

type loginResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
}

// Login exchanges Universal Auth credentials for an access token and its lifetime.
func (c *Client) Login(clientID, clientSecret string) (token string, ttl time.Duration, err error) {
	const op = "login"
	var out loginResponse
	resp, err := c.http.R().
		SetBody(loginRequest{ClientID: clientID, ClientSecret: clientSecret}).
		SetResult(&out).
		Post("/api/v1/auth/universal-auth/login")
	if err != nil {
		return "", 0, &RequestError{Operation: op, Err: err}
	}
	if resp.IsError() {
		return "", 0, newAPIError(op, resp)
	}
	if out.AccessToken == "" {
		return "", 0, &RequestError{Operation: op, Err: fmt.Errorf("login response had no access token")}
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

type listSignersResponse struct {
	Signers []Signer `json:"signers"`
}

// ListSigners returns every Signer the authenticated identity can use.
func (c *Client) ListSigners(token string) ([]Signer, error) {
	const op = "list-signers"
	var out listSignersResponse
	resp, err := c.http.R().
		SetAuthToken(token).
		SetQueryParam("limit", "100").
		SetResult(&out).
		Get("/api/v1/cert-manager/signers")
	if err != nil {
		return nil, &RequestError{Operation: op, Err: err}
	}
	if resp.IsError() {
		return nil, newAPIError(op, resp)
	}
	return out.Signers, nil
}

type signerCertResponse struct {
	CertificatePem string `json:"certificatePem"`
	SignerName     string `json:"signerName"`
}

// GetCertificate fetches a Signer's PEM certificate.
func (c *Client) GetCertificate(token, signerID string) (pem string, err error) {
	const op = "get-certificate"
	var out signerCertResponse
	resp, err := c.http.R().
		SetAuthToken(token).
		SetResult(&out).
		Get(fmt.Sprintf("/api/v1/cert-manager/signers/%s/certificate", url.PathEscape(signerID)))
	if err != nil {
		return "", &RequestError{Operation: op, Err: err}
	}
	if resp.IsError() {
		return "", newAPIError(op, resp)
	}
	return out.CertificatePem, nil
}

// SignParams is one sign request. Data is base64-encoded; the KSP always sends a pre-computed
// digest, so IsDigest is true.
type SignParams struct {
	DataB64          string         `json:"data"`
	SigningAlgorithm string         `json:"signingAlgorithm"`
	IsDigest         bool           `json:"isDigest"`
	ClientMetadata   ClientMetadata `json:"clientMetadata"`
}

type signResponse struct {
	Signature string `json:"signature"`
}

// Sign asks Infisical to sign a hash. Returns the base64-encoded signature.
func (c *Client) Sign(token, signerID string, p SignParams) (signatureB64 string, err error) {
	const op = "sign"
	var out signResponse
	resp, err := c.http.R().
		SetAuthToken(token).
		SetBody(p).
		SetResult(&out).
		Post(fmt.Sprintf("/api/v1/cert-manager/signers/%s/sign", url.PathEscape(signerID)))
	if err != nil {
		return "", &RequestError{Operation: op, Err: err}
	}
	if resp.IsError() {
		return "", newAPIError(op, resp)
	}
	return out.Signature, nil
}

type ApprovalRequestParams struct {
	Justification           string       `json:"justification"`
	RequestedSignings       int          `json:"requestedSignings,omitempty"`
	RequestedWindowDuration string       `json:"requestedWindowDuration,omitempty"`
	Scope                   SigningScope `json:"scope"`
}

type approvalRequestResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (c *Client) RequestApproval(token, signerID string, p ApprovalRequestParams) (id string, status string, err error) {
	const op = "request-approval"
	var out approvalRequestResponse
	resp, err := c.http.R().
		SetAuthToken(token).
		SetBody(p).
		SetResult(&out).
		Post(fmt.Sprintf("/api/v1/cert-manager/signers/%s/requests", url.PathEscape(signerID)))
	if err != nil {
		return "", "", &RequestError{Operation: op, Err: err}
	}
	if resp.IsError() {
		return "", "", newAPIError(op, resp)
	}
	return out.ID, out.Status, nil
}

type apiErrorBody struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Details struct {
		HasPendingRequest bool `json:"hasPendingRequest"`
	} `json:"details"`
}

func newAPIError(op string, resp *resty.Response) *APIError {
	msg := fmt.Sprintf("HTTP %d", resp.StatusCode())
	var body apiErrorBody
	if json.Unmarshal(resp.Body(), &body) == nil {
		if body.Message != "" {
			msg = body.Message
		} else if body.Error != "" {
			msg = body.Error
		}
	}
	return &APIError{
		Operation:         op,
		StatusCode:        resp.StatusCode(),
		Message:           msg,
		Code:              body.Error,
		HasPendingRequest: body.Details.HasPendingRequest,
	}
}
