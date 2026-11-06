package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/security"
)

func TestWorkloadIdentityKeepsCredentialQuotaAcrossRestartAndDisable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	account := ServiceAccount{ID: "agent", Name: "agent", Kind: "agent", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	identity := WorkloadIdentity{CredentialID: "workload-key", ServiceAccountID: "agent", ProviderID: "provider", Issuer: "issuer", Subject: "subject", Audience: "jolt"}
	if err := s.CreateWorkloadIdentity(ctx, identity, nil, "admin", "user", "correlation"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetWorkloadIdentityEnabled(ctx, "different-account", identity.CredentialID, false, "admin", "user", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account modified mapping: %v", err)
	}
	if version, err := s.Metadata(ctx, "minimum_security_version"); err != nil || version != "4" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	if _, _, err := s.AuthenticateServiceAccount(ctx, security.Digest("workload:workload-key")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("synthetic hash accepted as static credential: %v", err)
	}
	day := now.Format("2006-01-02")
	if _, err := s.ReserveAgentBytes(ctx, identity.CredentialID, day, 4096, 4096); err != nil {
		t.Fatal(err)
	}
	if err := s.SetWorkloadIdentityEnabled(ctx, identity.ServiceAccountID, identity.CredentialID, false, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled mapping resolved: %v", err)
	}
	duplicate := identity
	duplicate.CredentialID = "new-key"
	if err := s.CreateWorkloadIdentity(ctx, duplicate, nil, "admin", "user", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("disabled mapping recreated with fresh quota: %v", err)
	}
	if err := s.SetWorkloadIdentityEnabled(ctx, identity.ServiceAccountID, identity.CredentialID, true, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resolved, err := s.ActiveWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt")
	if err != nil || resolved.CredentialID != identity.CredentialID || resolved.ServiceAccountID != account.ID {
		t.Fatalf("mapping=%+v err=%v", resolved, err)
	}
	for _, expiry := range []time.Time{now.Add(time.Minute), now.Add(2 * time.Minute)} {
		gotAccount, token, err := s.AuthenticateWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt", expiry, now)
		if err != nil || gotAccount.ID != account.ID || token.ID != identity.CredentialID || token.ExpiresAt == nil || !token.ExpiresAt.Equal(expiry) {
			t.Fatalf("credential changed across assertions: account=%+v token=%+v err=%v", gotAccount, token, err)
		}
	}
	if _, _, err := s.AuthenticateWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt", now, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired assertion accepted: %v", err)
	}
	if _, err := s.ReserveAgentBytes(ctx, resolved.CredentialID, day, 1024, 4096); !errors.Is(err, ErrAgentQuota) {
		t.Fatalf("quota reset: %v", err)
	}
	expires := time.Now().Add(time.Hour)
	for index, token := range []ServiceAccountToken{
		{ID: "static-1", ServiceAccountID: "agent", TokenHash: security.Digest("static-1"), ExpiresAt: &expires, CreatedAt: time.Now()},
		{ID: "static-2", ServiceAccountID: "agent", TokenHash: security.Digest("static-2"), ExpiresAt: &expires, CreatedAt: time.Now()},
	} {
		if err := s.CreateServiceAccountToken(ctx, token, index == 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ActiveWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt"); err != nil {
		t.Fatalf("static key rotation revoked workload identity: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE service_account_tokens SET expires_at='malformed' WHERE id=?`, identity.CredentialID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed expiry accepted: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE service_account_tokens SET expires_at=NULL WHERE id=?`, identity.CredentialID); err != nil {
		t.Fatal(err)
	}
	for _, fields := range [][4]string{{"other", "issuer", "subject", "jolt"}, {"provider", "wrong", "subject", "jolt"}, {"provider", "issuer", "other", "jolt"}, {"provider", "issuer", "subject", "other"}} {
		if _, err := s.ActiveWorkloadIdentity(ctx, fields[0], fields[1], fields[2], fields[3]); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unexpected mapping %v: %v", fields, err)
		}
	}
	if _, err := s.DisableAgents(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled account resolved: %v", err)
	}
}

func TestWorkloadIdentityCreationAndSecurityVersionAreAtomic(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err := s.CreateServiceAccount(ctx, ServiceAccount{ID: "svc", Name: "svc", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	identity := WorkloadIdentity{CredentialID: "key", ServiceAccountID: "svc", ProviderID: "provider", Issuer: "issuer", Subject: "subject", Audience: "jolt"}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_workload_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateWorkloadIdentity(ctx, identity, nil, "admin", "user", ""); err == nil {
		t.Fatal("expected audit failure")
	}
	if _, err := s.Metadata(ctx, "minimum_security_version"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed transaction changed version: %v", err)
	}
	if tokens, err := s.ListServiceAccountTokens(ctx, "svc"); err != nil || len(tokens) != 0 {
		t.Fatalf("orphan credentials: %+v %v", tokens, err)
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_workload_audit`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateWorkloadIdentity(ctx, identity, nil, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeServiceAccountToken(ctx, "svc", "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActiveWorkloadIdentity(ctx, "provider", "issuer", "subject", "jolt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked mapping resolved: %v", err)
	}
}

func TestDuplicateWorkloadMappingsCannotCreateExtraCredentials(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err := s.CreateServiceAccount(ctx, ServiceAccount{ID: "svc", Name: "svc", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var succeeded atomic.Int32
	for _, id := range []string{"first", "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			identity := WorkloadIdentity{CredentialID: id, ServiceAccountID: "svc", ProviderID: "provider", Subject: "subject", Audience: "jolt"}
			err := s.CreateWorkloadIdentity(ctx, identity, nil, "admin", "user", "")
			if err == nil {
				succeeded.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()
	if succeeded.Load() != 1 {
		t.Fatalf("created=%d", succeeded.Load())
	}
	identities, err := s.ListWorkloadIdentities(ctx, "svc")
	if err != nil || len(identities) != 1 {
		t.Fatalf("duplicate or missing mappings: %+v %v", identities, err)
	}
	tokens, err := s.ListServiceAccountTokens(ctx, "svc")
	if err != nil || len(tokens) != 0 {
		t.Fatalf("workload credential appeared as static key: %+v %v", tokens, err)
	}
}

func TestPreviousV3ReaderRejectsWorkloadIdentity(t *testing.T) {
	checker := os.Getenv("JOLT_PREVIOUS_V3_CHECKER")
	if checker == "" {
		t.Skip("set JOLT_PREVIOUS_V3_CHECKER to a Control Tower store reader with security version 3")
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
	if output, err := exec.Command(checker, path).CombinedOutput(); err != nil {
		t.Fatalf("previous reader rejected legacy state: %v %s", err, output)
	}
	s, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.CreateServiceAccount(ctx, ServiceAccount{ID: "svc", Name: "svc", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	identity := WorkloadIdentity{CredentialID: "key", ServiceAccountID: "svc", ProviderID: "provider", Subject: "subject", Audience: "jolt"}
	if err := s.CreateWorkloadIdentity(ctx, identity, nil, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(checker, path).CombinedOutput(); err == nil || !strings.Contains(string(output), "unsupported security version") {
		t.Fatalf("previous reader accepted newer state: %v %s", err, output)
	}
}
