// Package infisical loads config, authenticates with a Machine Identity, lists Signers, fetches
// certificates, and asks Infisical to sign hashes. OS-agnostic.
package infisical

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// Environment variables.
const (
	// EnvConfigPath points at the config file; if unset, the default path is used.
	EnvConfigPath = "INFISICAL_CONFIG"
	// EnvClientID / EnvClientSecret hold the Machine Identity (Universal Auth) credentials.
	EnvClientID     = "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"
	EnvClientSecret = "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"
	// EnvServerURL overrides server_url from the config file.
	EnvServerURL = "INFISICAL_SERVER_URL"
	// EnvToken holds an Infisical access token (a user or machine identity JWT) used directly
	EnvToken = "INFISICAL_TOKEN"
)

// Auth methods.
const (
	AuthMethodUniversalAuth = "universal-auth"
	AuthMethodToken         = "token"
)

// TLSConfig controls how the client trusts the Infisical server (for self-hosted instances).
type TLSConfig struct {
	CACertPath string `json:"ca_cert_path"`
	SkipVerify bool   `json:"skip_verify"`
}

// CacheConfig sets in-memory cache lifetimes. Zero means "use the default".
type CacheConfig struct {
	TokenTTLSeconds  int `json:"token_ttl_seconds"`
	CertTTLSeconds   int `json:"cert_ttl_seconds"`
	SignerTTLSeconds int `json:"signer_ttl_seconds"`
}

// AuthConfig holds the credentials used to authenticate with Infisical. Prefer the environment
// variables.
type AuthConfig struct {
	Method       string `json:"method"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Token        string `json:"token"`
}

// Config is the on-disk JSON config plus environment overrides.
type Config struct {
	ServerURL string      `json:"server_url"`
	Auth      AuthConfig  `json:"auth"`
	TLS       TLSConfig   `json:"tls"`
	Cache     CacheConfig `json:"cache"`
	LogLevel  string      `json:"log_level"`
	LogFile   string      `json:"log_file"`
}

func (c *Config) setDefaults() {
	if c.Cache.TokenTTLSeconds == 0 {
		c.Cache.TokenTTLSeconds = 300
	}
	if c.Cache.CertTTLSeconds == 0 {
		c.Cache.CertTTLSeconds = 3600
	}
	if c.Cache.SignerTTLSeconds == 0 {
		c.Cache.SignerTTLSeconds = 300
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Auth.Method == "" {
		if c.Auth.Token != "" {
			c.Auth.Method = AuthMethodToken
		} else {
			c.Auth.Method = AuthMethodUniversalAuth
		}
	}
	// A KSP has no console, so default the log file to a well-known path.
	if c.LogFile == "" {
		c.LogFile = DefaultLogPath()
	}
}

func (c *Config) applyEnvOverrides() {
	if v := os.Getenv(EnvServerURL); v != "" {
		c.ServerURL = v
	}
	if v := os.Getenv(EnvClientID); v != "" {
		c.Auth.ClientID = v
	}
	if v := os.Getenv(EnvClientSecret); v != "" {
		c.Auth.ClientSecret = v
	}
	// A token in the environment selects token auth and takes precedence over Universal Auth.
	if v := os.Getenv(EnvToken); v != "" {
		c.Auth.Token = v
		c.Auth.Method = AuthMethodToken
	}
}

func (c *Config) validate() error {
	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	parsed, err := url.Parse(c.ServerURL)
	if err != nil {
		return fmt.Errorf("server_url is not a valid URL: %w", err)
	}
	if scheme := strings.ToLower(parsed.Scheme); scheme != "http" && scheme != "https" {
		return fmt.Errorf("server_url scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("server_url must include a host")
	}
	switch c.Auth.Method {
	case AuthMethodUniversalAuth, AuthMethodToken:
	default:
		return fmt.Errorf("unsupported auth method: %s (must be 'universal-auth' or 'token')", c.Auth.Method)
	}
	return nil
}

// DefaultConfigPath is the config file path used when no config env var is set.
func DefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return programData + `\Infisical\config.json`
	}
	return "/etc/infisical/ksp.conf"
}

// DefaultLogPath is where the KSP writes its log when the config does not set log_file.
func DefaultLogPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return programData + `\Infisical\ksp.log`
	}
	return ""
}

// ConfigPath resolves the config file path from the environment, falling back to the default.
func ConfigPath() string {
	if p := os.Getenv(EnvConfigPath); p != "" {
		return p
	}
	return DefaultConfigPath()
}

// LoadConfig reads and validates the config file, then applies environment overrides. When no
// config path is set explicitly and the default file is absent, configuration falls back to
// environment variables alone (INFISICAL_SERVER_URL plus the credential variables), so a
// config file is optional.
func LoadConfig() (*Config, error) {
	allowMissing := os.Getenv(EnvConfigPath) == ""
	return loadConfigFrom(ConfigPath(), allowMissing)
}

// loadConfigFrom reads config from an explicit path. When allowMissing is true, a non-existent
// file is treated as an empty config so environment variables can supply everything.
func loadConfigFrom(path string, allowMissing bool) (*Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
		}
	case allowMissing && errors.Is(err, os.ErrNotExist):
		// No config file at the default path: rely on environment variables.
	default:
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	cfg.setDefaults()
	cfg.applyEnvOverrides()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
