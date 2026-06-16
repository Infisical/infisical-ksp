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
	cfg, err := loadConfigFrom(path, false)
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
			if _, err := loadConfigFrom(writeConfig(t, body), false); err == nil {
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
	cfg, err := loadConfigFrom(path, false)
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

func TestLoadConfigTokenAuthFromConfig(t *testing.T) {
	path := writeConfig(t, `{"server_url":"https://app.infisical.com","auth":{"method":"token","token":"jwt-abc"}}`)
	cfg, err := loadConfigFrom(path, false)
	if err != nil {
		t.Fatalf("loadConfigFrom: %v", err)
	}
	if cfg.Auth.Method != AuthMethodToken || cfg.Auth.Token != "jwt-abc" {
		t.Errorf("token auth not loaded: %+v", cfg.Auth)
	}
}

func TestLoadConfigTokenInferredFromTokenField(t *testing.T) {
	// No auth.method set: a token in the config should select token auth on its own.
	path := writeConfig(t, `{"server_url":"https://app.infisical.com","auth":{"token":"jwt-abc"}}`)
	cfg, err := loadConfigFrom(path, false)
	if err != nil {
		t.Fatalf("loadConfigFrom: %v", err)
	}
	if cfg.Auth.Method != AuthMethodToken {
		t.Errorf("token in config should infer token auth, got method %q", cfg.Auth.Method)
	}
}

func TestTokenAuthMissingTokenIsLazy(t *testing.T) {
	path := writeConfig(t, `{"server_url":"https://app.infisical.com","auth":{"method":"token"}}`)
	cfg, err := loadConfigFrom(path, false)
	if err != nil {
		t.Fatalf("loadConfigFrom should not fail for token without token (lazy): %v", err)
	}
	// ...but ensureToken reports a clear error when it's actually needed.
	sess, err := NewSession(cfg)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if _, err := sess.ensureToken(); err == nil {
		t.Fatal("ensureToken should error when token auth has no token")
	}
}

func TestLoadConfigTokenEnvSelectsTokenAuth(t *testing.T) {
	t.Setenv(EnvServerURL, "https://app.infisical.com")
	t.Setenv(EnvToken, "jwt-from-env")

	missing := filepath.Join(t.TempDir(), "none.json")
	cfg, err := loadConfigFrom(missing, true)
	if err != nil {
		t.Fatalf("loadConfigFrom: %v", err)
	}
	if cfg.Auth.Method != AuthMethodToken {
		t.Errorf("env token should select token auth, got method %q", cfg.Auth.Method)
	}
	if cfg.Auth.Token != "jwt-from-env" {
		t.Errorf("token from env = %q", cfg.Auth.Token)
	}
}

func TestLoadConfigEnvOnlyNoFile(t *testing.T) {
	t.Setenv(EnvServerURL, "https://app.infisical.com")
	t.Setenv(EnvClientID, "env-client-id")
	t.Setenv(EnvClientSecret, "env-secret")

	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	cfg, err := loadConfigFrom(missing, true)
	if err != nil {
		t.Fatalf("loadConfigFrom with missing file: %v", err)
	}
	if cfg.ServerURL != "https://app.infisical.com" {
		t.Errorf("server_url from env = %q", cfg.ServerURL)
	}
	if cfg.Auth.ClientID != "env-client-id" || cfg.Auth.ClientSecret != "env-secret" {
		t.Errorf("credentials from env failed: %+v", cfg.Auth)
	}

	// A missing file is still an error when the path was set explicitly.
	if _, err := loadConfigFrom(missing, false); err == nil {
		t.Fatal("expected error for missing file when allowMissing=false, got nil")
	}
}
