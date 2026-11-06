package filesystem

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretScanPrefix(t *testing.T) {
	for _, tc := range []struct{ name, value, kind string }{
		{"pem", "-----BEGIN PRIVATE KEY-----", "private_key"},
		{"aws", "AKIA" + strings.Repeat("A", 16), "aws_access_key"},
		{"github", "ghp_" + strings.Repeat("a", 36), "github_token"},
		{"jwt", "eyJ" + strings.Repeat("A", 12) + "." + strings.Repeat("B", 12) + "." + strings.Repeat("C", 12), "jwt"},
		{"assignment", "password = fictional-value", "credential_assignment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(path, []byte(tc.value), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			err = ScanSecretPrefix(file)
			var detected *SecretError
			if !errors.As(err, &detected) || detected.Kind != tc.kind || strings.Contains(err.Error(), tc.value) {
				t.Fatalf("scan = %v", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 64<<10)+"-----BEGIN PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := ScanSecretPrefix(file); err != nil {
		t.Fatalf("outside prefix was unexpectedly scanned: %v", err)
	}
}

func TestArchiveRescansAfterPlanBeforeWritingEntry(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	name := filepath.Join(root, "data.txt")
	if err := os.WriteFile(name, []byte("ordinary content"), 0600); err != nil {
		t.Fatal(err)
	}
	options := ArchiveOptions{ScanSecrets: true}
	if _, err := service.PlanArchive(context.Background(), mountID, "", options); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("-----BEGIN PRIVATE KEY-----"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_, err := service.Archive(context.Background(), mountID, "", options, &output)
	if !errors.Is(err, ErrSecretDetected) || bytes.Contains(output.Bytes(), []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("changed entry was not blocked: %v", err)
	}
}
