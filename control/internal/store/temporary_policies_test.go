package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
)

func TestTemporaryPoliciesExpireAndNeverBecomePermanentThroughLegacyReplacement(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := s.CreateServiceAccount(ctx, ServiceAccount{ID: "agent", Name: "agent", Kind: "agent", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePolicy(ctx, Policy{ID: "policy", Name: "policy", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n/files/**", Capabilities: []string{"read", "update"}}}}); err != nil {
		t.Fatal(err)
	}
	grant, err := s.GrantTemporaryPolicy(ctx, "service_account", "agent", "policy", "admin", "user", "test", 15*time.Minute)
	if err != nil || grant.ExpiresAt.Before(now.Add(14*time.Minute)) {
		t.Fatalf("grant: %+v %v", grant, err)
	}
	policies, err := s.RBACPoliciesForSubject(ctx, "service_account", "agent")
	if err != nil || len(policies) != 1 {
		t.Fatalf("active grant missing: %+v %v", policies, err)
	}
	ids, err := s.SubjectPolicyIDs(ctx, "service_account", "agent")
	if err != nil || len(ids) != 0 {
		t.Fatalf("temporary grant exposed as permanent: %+v %v", ids, err)
	}
	if err := s.SetSubjectPolicies(ctx, "service_account", "agent", ids); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE temporary_policy_assignments SET expires_at_ns=? WHERE policy_id='policy'`, time.Now().UTC().Add(-time.Second).UnixNano()); err != nil {
		t.Fatal(err)
	}
	policies, err = s.RBACPoliciesForSubject(ctx, "service_account", "agent")
	if err != nil || len(policies) != 0 {
		t.Fatalf("expired grant remains effective: %+v %v", policies, err)
	}
	if _, err := s.GrantTemporaryPolicy(ctx, "service_account", "agent", "policy", "admin", "user", "test", time.Hour+time.Second); err == nil {
		t.Fatal("accepted a grant longer than one hour")
	}
	if err := s.CreateUser(ctx, User{ID: "operator", Username: "operator", PasswordHash: "hash", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GrantTemporaryPolicy(ctx, "user", "operator", "policy", "admin", "user", "test", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	policies, err = s.RBACPoliciesForSubject(ctx, "user", "operator")
	if err != nil || len(policies) != 1 {
		t.Fatalf("temporary user policy missing: %+v %v", policies, err)
	}
	if _, err := s.db.Exec(`UPDATE temporary_policy_assignments SET expires_at_ns=? WHERE subject_type='user'`, time.Now().UTC().Add(-time.Second).UnixNano()); err != nil {
		t.Fatal(err)
	}
	policies, err = s.RBACPoliciesForSubject(ctx, "user", "operator")
	if err != nil || len(policies) != 0 {
		t.Fatalf("expired user policy remains effective: %+v %v", policies, err)
	}
}

func TestInactiveGroupDoesNotGrantPolicies(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, now := context.Background(), time.Now().UTC()
	if err := s.CreateServiceAccount(ctx, ServiceAccount{ID: "svc", Name: "svc", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePolicy(ctx, Policy{ID: "policy", Name: "policy", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccessGroup(ctx, AccessGroup{ID: "inactive", Name: "inactive", Enabled: false, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAccessGroupPolicies(ctx, "inactive", []string{"policy"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetServiceAccountGroups(ctx, "svc", []string{"inactive"}); err != nil {
		t.Fatal(err)
	}
	policies, err := s.RBACPoliciesForSubject(ctx, "service_account", "svc")
	if err != nil || len(policies) != 0 {
		t.Fatalf("inactive group granted policies: %+v %v", policies, err)
	}
}
