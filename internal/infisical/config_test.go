package infisical

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	path := writeConfig(t, `{"server_url":"https://app.infisical.com"}`)
	cfg, err := loadConfigFrom(path)
	if err != nil {
		t.Fatalf("loadConfigFrom: %v", err)
	}
	if cfg.Auth.Method != "universal-auth" {
		t.Errorf("auth method default = %q, want universal-auth", cfg.Auth.Method)
	}
	if cfg.Cache.TokenTTLSeconds != 300 || cfg.Cache.CertTTLSeconds != 3600 || cfg.Cache.SignerTTLSeconds != 300 {
		t.Errorf("cache defaults not applied: %+v", cfg.Cache)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log level default = %q, want info", cfg.LogLevel)
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	cases := map[string]string{
		"missing server_url": `{}`,
		"bad scheme":         `{"server_url":"ftp://example.com"}`,
		"no host":            `{"server_url":"https://"}`,
		"bad auth method":    `{"server_url":"https://app.infisical.com","auth":{"method":"oidc"}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfigFrom(writeConfig(t, body)); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	t.Setenv(EnvServerURL, "https://self-hosted.example.com")
	t.Setenv(EnvClientID, "env-client-id")
	t.Setenv(EnvClientSecret, "env-secret")

	path := writeConfig(t, `{"server_url":"https://app.infisical.com"}`)
	cfg, err := loadConfigFrom(path)
	if err != nil {
		t.Fatalf("loadConfigFrom: %v", err)
	}
	if cfg.ServerURL != "https://self-hosted.example.com" {
		t.Errorf("server_url override = %q", cfg.ServerURL)
	}
	if cfg.Auth.ClientID != "env-client-id" || cfg.Auth.ClientSecret != "env-secret" {
		t.Errorf("credential override failed: %+v", cfg.Auth)
	}
}
