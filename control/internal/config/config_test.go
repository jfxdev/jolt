package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
