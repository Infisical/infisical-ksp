// Package infisical loads config, authenticates with a Machine Identity, lists Signers, fetches
// certificates, and asks Infisical to sign hashes. OS-agnostic.
package infisical

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
)

// Environment variables.
const (
	// EnvConfigPath points at the KSP config file; if unset, the default path is used.
	EnvConfigPath = "INFISICAL_KSP_CONFIG"
	// EnvClientID / EnvClientSecret hold the Machine Identity (Universal Auth) credentials.
	EnvClientID     = "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID"
	EnvClientSecret = "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"
	// EnvServerURL overrides server_url from the config file.
	EnvServerURL = "INFISICAL_KSP_SERVER_URL"
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

// AuthConfig holds the Machine Identity credentials. Prefer the environment variables.
type AuthConfig struct {
	Method       string `json:"method"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
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
		c.Auth.Method = "universal-auth"
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
	if c.Auth.Method != "universal-auth" {
		return fmt.Errorf("unsupported auth method: %s (must be 'universal-auth')", c.Auth.Method)
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

// LoadConfig reads and validates the config file, then applies environment overrides.
func LoadConfig() (*Config, error) {
	return loadConfigFrom(ConfigPath())
}

// loadConfigFrom reads config from an explicit path.
func loadConfigFrom(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	cfg.setDefaults()
	cfg.applyEnvOverrides()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}
