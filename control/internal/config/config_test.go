package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/signedauth"
)

func TestAuthorizationSigningKeyFile(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "authorization.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readAuthorizationSigningKey("current", file)
	if err != nil || !got.Equal(private) {
		t.Fatalf("private key not loaded: %v", err)
	}
	t.Setenv("CONTROL_TOWER_ADMIN_PASSWORD", "a-secure-admin-password")
	t.Setenv("CONTROL_TOWER_DB_ENCRYPTION_KEY", "a-secure-encryption-key-that-is-long-enough")
	t.Setenv("CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_ID", "current")
	t.Setenv("CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_FILE", file)
	cfg, err := Load()
	if err != nil || cfg.AuthorizationSigningKeyID != "current" || !cfg.AuthorizationSigningKey.Equal(private) {
		t.Fatalf("key configuration failed: %v", err)
	}
	binding := signedauth.Binding{ActorID: "actor", CredentialID: "credential", Operation: "read", RequestID: "request", SourceNodeID: "node", SourceMountID: "mount", SourceRoot: "."}
	claims := signedauth.Claims{Version: signedauth.Version, KeyID: cfg.AuthorizationSigningKeyID, Binding: binding, IssuedAt: 1700000000, ExpiresAt: 1700000030, Context: json.RawMessage(`{"version":1,"rules":[]}`)}
	token, err := signedauth.Sign(claims, cfg.AuthorizationSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"current": private.Public().(ed25519.PublicKey)}
	if _, _, err := signedauth.Verify(token, keys, binding, "node", time.Unix(claims.IssuedAt, 0)); err != nil {
		t.Fatalf("configured key failed signing: %v", err)
	}
	encodedConfig, err := json.Marshal(cfg)
	if err != nil || strings.Contains(string(encodedConfig), "AuthorizationSigningKey\"") {
		t.Fatal("private signing key was serialized")
	}
	t.Setenv("CONTROL_TOWER_AUTHORIZATION_SIGNING_KEY_FILE", "")
	if _, err := Load(); err == nil {
		t.Fatal("partial key configuration accepted")
	}
	for _, tc := range []struct{ id, file string }{{"", file}, {"bad/id", file}, {"current", ""}, {"current", file + "-missing"}} {
		if _, err := readAuthorizationSigningKey(tc.id, tc.file); err == nil {
			t.Fatalf("invalid key source accepted: %+v", tc)
		}
	}
	if err := os.WriteFile(file, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAuthorizationSigningKey("current", file); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestValidateNodeEndpoint(t *testing.T) {
	got, err := ValidateNodeEndpoint("https://node.example.test:8443/api?ignored=true")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://node.example.test:8443" {
		t.Fatalf("endpoint = %q", got)
	}
}

func TestValidateNodeEndpointRejectsUnsupportedScheme(t *testing.T) {
	if _, err := ValidateNodeEndpoint("file:///etc/passwd"); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestSecretValueSources(t *testing.T) {
	const key = "CONTROL_TOWER_TEST_SECRET"
	t.Setenv(key, " environment-secret \n")
	t.Setenv(key+"_FILE", "")
	value, err := SecretValue(key)
	if err != nil || value != "environment-secret" {
		t.Fatalf("environment secret = %q, %v", value, err)
	}
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte(" file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(key+"_FILE", file)
	if _, err := SecretValue(key); err == nil {
		t.Fatal("ambiguous secret source accepted")
	}
	t.Setenv(key, "")
	value, err = SecretValue(key)
	if err != nil || value != "file-secret" {
		t.Fatalf("file secret = %q, %v", value, err)
	}
	t.Setenv(key+"_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := SecretValue(key); err == nil {
		t.Fatal("missing secret file accepted")
	}
}

func TestLoadSecretsFromFiles(t *testing.T) {
	dir := t.TempDir()
	secrets := map[string]string{
		"CONTROL_TOWER_ADMIN_PASSWORD":    "a-secure-admin-password\n",
		"CONTROL_TOWER_DB_ENCRYPTION_KEY": "a-secure-encryption-key-that-is-long-enough\n",
		"CONTROL_TOWER_METRICS_TOKEN":     "a-secure-metrics-token\n",
	}
	for key, secret := range secrets {
		file := filepath.Join(dir, key)
		if err := os.WriteFile(file, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, "")
		t.Setenv(key+"_FILE", file)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminPassword != "a-secure-admin-password" || cfg.MetricsToken != "a-secure-metrics-token" || len(cfg.EncryptionKey) != 32 {
		t.Fatal("file-backed secrets were not loaded")
	}
}

func TestTransferMaxSourcePathsUsesDefaultAndRejectsInvalidValues(t *testing.T) {
	t.Setenv("CONTROL_TOWER_ADMIN_PASSWORD", "a-secure-admin-password")
	t.Setenv("CONTROL_TOWER_DB_ENCRYPTION_KEY", "a-secure-encryption-key-that-is-long-enough")
	t.Setenv("TRANSFER_MAX_SOURCE_PATHS", "")
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.TransferMaxSourcePaths != 1000 {
		t.Fatalf("default max source paths = %d", config.TransferMaxSourcePaths)
	}
	t.Setenv("TRANSFER_MAX_SOURCE_PATHS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid transfer max source paths error")
	}
}

func TestAgentProxyAndAuditConfiguration(t *testing.T) {
	t.Setenv("CONTROL_TOWER_ADMIN_PASSWORD", "a-secure-admin-password")
	t.Setenv("CONTROL_TOWER_DB_ENCRYPTION_KEY", "a-secure-encryption-key-that-is-long-enough")
	t.Setenv("CONTROL_TOWER_TRUSTED_PROXIES", "10.0.0.1/8, 2001:db8::/32")
	t.Setenv("CONTROL_TOWER_AUDIT_RETENTION_DAYS", "45")
	t.Setenv("CONTROL_TOWER_AUDIT_SEARCH_QUERY", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0].String() != "10.0.0.0/8" || cfg.AuditRetentionDays != 45 || !cfg.AuditSearchQuery {
		t.Fatalf("agent config: %+v", cfg)
	}
	t.Setenv("CONTROL_TOWER_TRUSTED_PROXIES", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("invalid proxy CIDR accepted")
	}
	t.Setenv("CONTROL_TOWER_TRUSTED_PROXIES", "")
	t.Setenv("CONTROL_TOWER_AUDIT_RETENTION_DAYS", "-1")
	if _, err := Load(); err == nil {
		t.Fatal("negative audit retention accepted")
	}
}
