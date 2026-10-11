package config

import "testing"

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
