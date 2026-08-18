package recovery_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/recovery"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/store"
)

func TestControlRestoreDiagnosticsValidateKeyAdminAndNodeCredentials(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	storage, err := store.Open(filepath.Join(dataDir, "control.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	keyCheck, err := security.Encrypt(key, security.EncryptionKeyCheck)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetMetadata(context.Background(), "encryption_key_check", keyCheck); err != nil {
		t.Fatal(err)
	}
	passwordHash, err := security.HashPassword("restore-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.EnsureAdmin(context.Background(), "admin", "admin", passwordHash); err != nil {
		t.Fatal(err)
	}
	token, err := security.Encrypt(key, "node-operational-token")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := storage.SaveNode(context.Background(), store.Node{
		ID: "node-1", Name: "Node", Endpoint: "https://node.test", TokenEncrypted: token,
		State: "offline", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	report, err := recovery.DiagnoseRestore(context.Background(), dataDir, key)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "ok" || !report.EncryptionKeyValid ||
		report.EnabledAdminCount != 1 || report.NodeCount != 1 ||
		report.NodeCredentialsValid != 1 {
		t.Fatalf("unexpected restore report: %+v", report)
	}
}

func TestControlRestoreDiagnosticsRejectWrongEncryptionKey(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	storage, err := store.Open(filepath.Join(dataDir, "control.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	keyCheck, err := security.Encrypt(key, security.EncryptionKeyCheck)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.SetMetadata(context.Background(), "encryption_key_check", keyCheck); err != nil {
		t.Fatal(err)
	}
	passwordHash, err := security.HashPassword("restore-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.EnsureAdmin(context.Background(), "admin", "admin", passwordHash); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	wrongKey := []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	report, err := recovery.DiagnoseRestore(context.Background(), dataDir, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "error" || report.EncryptionKeyValid ||
		!hasControlIssue(report.Issues, "encryption_key_invalid") {
		t.Fatalf("expected key failure: %+v", report)
	}
}

func hasControlIssue(issues []recovery.DiagnosticIssue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
