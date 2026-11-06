package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShareCreatorIdentityAndSecurityVersionAreAtomic(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	legacy := Share{ID: "legacy", TokenHash: "legacy-hash", NodeID: "node", MountID: "m", Path: "file", Kind: "file", Name: "file", CreatedBy: "user", CreatedAt: now}
	if err := s.CreateShare(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetShare(ctx, legacy.ID)
	if err != nil || stored.CreatedByType != "user" || stored.CreatedCredentialID != "" {
		t.Fatalf("legacy identity: %+v %v", stored, err)
	}
	bad := legacy
	bad.CreatedByType, bad.CreatedCredentialID = "service_account", "key"
	if err := s.CreateShare(ctx, bad); err == nil {
		t.Fatal("duplicate share accepted")
	}
	if _, err := s.Metadata(ctx, "minimum_security_version"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed insert changed security version: %v", err)
	}
	bad.ID, bad.TokenHash, bad.CreatedBy = "automation", "automation-hash", "svc"
	if err := s.CreateShare(ctx, bad); err != nil {
		t.Fatal(err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err != nil || version != "3" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stored, err = s.GetShare(ctx, bad.ID)
	if err != nil || stored.CreatedByType != "service_account" || stored.CreatedCredentialID != "key" {
		t.Fatalf("automation identity after restart: %+v %v", stored, err)
	}
}

func TestActiveShareCredentialRejectsRevocationAndMalformedExpiry(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	account := ServiceAccount{ID: "svc", Name: "svc", Kind: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Minute)
	if err := s.CreateServiceAccountToken(ctx, ServiceAccountToken{ID: "key", ServiceAccountID: account.ID, Name: "key", TokenHash: "digest", ExpiresAt: &expires, CreatedAt: now}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveServiceAccountToken(ctx, account.ID, "key", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveServiceAccountToken(ctx, account.ID, "key", expires); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired key accepted: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE service_account_tokens SET expires_at='invalid' WHERE id='key'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveServiceAccountToken(ctx, account.ID, "key", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed expiry accepted: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE service_account_tokens SET expires_at=NULL, revoked_at='invalid' WHERE id='key'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetActiveServiceAccountToken(ctx, account.ID, "key", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked key accepted: %v", err)
	}
}

func TestPreviousControlReaderRejectsAutomationShareIdentity(t *testing.T) {
	checker := os.Getenv("JOLT_PREVIOUS_CONTROL_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_PREVIOUS_CONTROL_CHECKER to a reader built before automation share identity")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, path).CombinedOutput(); err != nil {
		t.Fatalf("previous reader rejected legacy state: %v %s", err, out)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	share := Share{ID: "share", TokenHash: "hash", NodeID: "node", MountID: "m", Path: "file", Kind: "file", Name: "file", CreatedBy: "svc", CreatedByType: "service_account", CreatedCredentialID: "key", CreatedAt: time.Now().UTC()}
	if err := s.CreateShare(ctx, share); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(checker, path).CombinedOutput(); err == nil || !strings.Contains(string(out), "unsupported security version") {
		t.Fatalf("previous reader did not reject newer state: %v %s", err, out)
	}
}
