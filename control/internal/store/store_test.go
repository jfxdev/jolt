package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
)

var testDatabaseKey = []byte("0123456789abcdef0123456789abcdef")

func TestMigrationRenamesLegacyWorkerColumnsAndPolicyPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	storage, err := Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, statement := range []string{
		`ALTER TABLE connections RENAME COLUMN issuer_node_id TO issuer_worker_id`,
		`ALTER TABLE connections RENAME COLUMN target_node_id TO target_worker_id`,
		`INSERT INTO policies(id,name,description,created_at,updated_at) VALUES('legacy-policy','legacy','', '` + now + `','` + now + `')`,
		`INSERT INTO policy_rules(policy_id,path,capabilities,position) VALUES('legacy-policy','workers/node-a','["list"]',0)`,
	} {
		if _, err := storage.db.Exec(statement); err != nil {
			storage.Close()
			t.Fatal(err)
		}
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}

	storage, err = Open(path, testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	policy, err := storage.GetPolicy(context.Background(), "legacy-policy")
	if err != nil {
		t.Fatal(err)
	}
	if got := policy.Rules[0].Path; got != "nodes/node-a" {
		t.Fatalf("migrated policy path = %q, want nodes/node-a", got)
	}
	var nodeColumnCount int
	if err := storage.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('connections')
WHERE name IN ('issuer_node_id','target_node_id')`).Scan(&nodeColumnCount); err != nil {
		t.Fatal(err)
	}
	if nodeColumnCount != 2 {
		t.Fatalf("node column count = %d, want 2", nodeColumnCount)
	}
}

func TestDeleteNodeRemovesConnectionOrchestrationAndPreservesAudit(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	for _, node := range []Node{
		{ID: "node-a", Name: "Node A", Endpoint: "https://a.example.test", TokenEncrypted: "encrypted-a", State: "online", CreatedAt: now, UpdatedAt: now},
		{ID: "node-b", Name: "Node B", Endpoint: "https://b.example.test", TokenEncrypted: "encrypted-b", State: "online", CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.SaveNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.SaveConnection(ctx, Connection{
		RequestID: "request-1", InviteID: "invite-1",
		IssuerNodeID: "node-a", TargetNodeID: "node-b",
		InviteTokenEncrypted: "encrypted-invite", IssuerFingerprint: "fingerprint",
		Status: "pending_review", ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	storage.Audit(ctx, "admin-1", "create", "nodes/node-a", "allowed", "cor-1")

	if err := storage.DeleteNode(ctx, "node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.GetNode(ctx, "node-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted node lookup error = %v", err)
	}
	if _, err := storage.GetNode(ctx, "node-b"); err != nil {
		t.Fatalf("unrelated node was affected: %v", err)
	}
	if _, err := storage.GetConnection(ctx, "request-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("connection orchestration lookup error = %v", err)
	}
	var auditCount int
	if err := storage.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE resource='nodes/node-a'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit event count = %d, want 1", auditCount)
	}
}

func TestDeleteNodeReturnsNotFound(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	if err := storage.DeleteNode(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteNode error = %v, want ErrNotFound", err)
	}
}

func TestAccessGroupLifecycleScopesPoliciesAndAPIKeys(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := storage.SaveNode(ctx, Node{ID: "node-a", Name: "Node A", Endpoint: "https://a.example.test", TokenEncrypted: "encrypted", State: "online", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	policy := Policy{ID: "policy-files", Name: "files", Description: "", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{{Path: "nodes/node-a/files/mounts/media", Capabilities: []string{"read"}}}}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	group := AccessGroup{ID: "group-media", Name: "media", Description: "", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateAccessGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupNodes(ctx, group.ID, []string{"node-a"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetAccessGroupPolicies(ctx, group.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	account := ServiceAccount{ID: "svc-media", Name: "media-key", Description: "", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetServiceAccountGroups(ctx, account.ID, []string{group.ID}); err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateServiceAccountToken(ctx, ServiceAccountToken{ID: "key-media", ServiceAccountID: account.ID, Name: "primary", TokenHash: "token-hash", CreatedAt: now}, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := storage.GetAccessGroup(ctx, group.ID)
	if err != nil || len(loaded.NodeIDs) != 1 || len(loaded.PolicyIDs) != 1 {
		t.Fatalf("group=%+v err=%v", loaded, err)
	}
	policies, err := storage.RBACPoliciesForSubject(ctx, "service_account", account.ID)
	if err != nil || len(policies) != 1 || policies[0].ID != policy.ID {
		t.Fatalf("policies=%+v err=%v", policies, err)
	}
	if err := storage.DeleteAccessGroup(ctx, group.ID); err != nil {
		t.Fatal(err)
	}
	ids, err := storage.ServiceAccountGroupIDs(ctx, account.ID, false)
	if err != nil || len(ids) != 0 {
		t.Fatalf("group ids=%v err=%v", ids, err)
	}
}

func TestServiceAccountGroupsFilterInactiveAndPreserveLinksOnInvalidUpdate(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	account := ServiceAccount{ID: "svc-1", Name: "svc-1", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	for _, group := range []AccessGroup{
		{ID: "group-active", Name: "group-active", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "group-inactive", Name: "group-inactive", Enabled: false, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateAccessGroup(ctx, group); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.SetServiceAccountGroups(ctx, account.ID, []string{"group-active", "group-inactive"}); err != nil {
		t.Fatal(err)
	}
	all, err := storage.ServiceAccountGroupIDs(ctx, account.ID, false)
	if err != nil || len(all) != 2 {
		t.Fatalf("all=%v err=%v", all, err)
	}
	active, err := storage.ServiceAccountGroupIDs(ctx, account.ID, true)
	if err != nil || len(active) != 1 || active[0] != "group-active" {
		t.Fatalf("active=%v err=%v", active, err)
	}
	if err := storage.SetServiceAccountGroups(ctx, account.ID, []string{"missing-group"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalid update error=%v", err)
	}
	unchanged, err := storage.ServiceAccountGroupIDs(ctx, account.ID, false)
	if err != nil || len(unchanged) != 2 {
		t.Fatalf("links changed after failed update: %v err=%v", unchanged, err)
	}
	if err := storage.SetServiceAccountGroups(ctx, "missing-account", []string{"group-active"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing account error=%v", err)
	}
}

func TestListAuditEventsFiltersPaginatesAndIncludesDecisionContext(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	storage.AuditActor(ctx, "user-1", "user", "create", "nodes/node-a", "allowed", "cor-first")
	storage.AuditDecision(ctx, "service-1", "service_account", "authorize",
		"nodes/node-a/files/mounts/media", "denied", "cor-decision",
		[]string{"policy-read", "policy-deny"}, "nodes/node-a/files/mounts/media", "create")
	storage.AuditActor(ctx, "user-1", "user", "delete", "nodes/node-a", "allowed", "cor-last")

	page, hasMore, err := storage.ListAuditEvents(ctx, AuditQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !hasMore || len(page) != 2 || page[0].CorrelationID != "cor-last" ||
		page[1].CorrelationID != "cor-decision" {
		t.Fatalf("unexpected first page: events=%+v has_more=%v", page, hasMore)
	}
	if page[1].ActorType != "service_account" || page[1].Capability != "create" ||
		page[1].EvaluatedPath != "nodes/node-a/files/mounts/media" ||
		len(page[1].PolicyIDs) != 2 {
		t.Fatalf("decision context was not preserved: %+v", page[1])
	}
	next, hasMore, err := storage.ListAuditEvents(ctx, AuditQuery{
		BeforeID: page[len(page)-1].ID, Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(next) != 1 || next[0].CorrelationID != "cor-first" {
		t.Fatalf("unexpected next page: events=%+v has_more=%v", next, hasMore)
	}
	filtered, _, err := storage.ListAuditEvents(ctx, AuditQuery{
		ActorType: "service_account", Result: "denied", CorrelationID: "cor-decision",
	})
	if err != nil || len(filtered) != 1 || filtered[0].Action != "authorize" {
		t.Fatalf("filtered events=%+v err=%v", filtered, err)
	}
}

func TestUserLifecycleProtectsLastAdminAndPreservesAudit(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	if err := storage.EnsureAdmin(ctx, "admin-1", "admin", "hash-1"); err != nil {
		t.Fatal(err)
	}
	if err := storage.DeleteUser(ctx, "admin-1"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting the last admin returned %v", err)
	}
	admin, err := storage.GetUser(ctx, "admin-1")
	if err != nil {
		t.Fatal(err)
	}
	admin.Enabled = false
	admin.UpdatedAt = time.Now().UTC()
	if err := storage.UpdateUser(ctx, admin, ""); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disabling the last admin returned %v", err)
	}

	now := time.Now().UTC()
	second := User{
		ID: "admin-2", Username: "backup-admin", PasswordHash: "hash-2",
		Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateUser(ctx, second); err != nil {
		t.Fatal(err)
	}
	storage.Audit(ctx, "admin-2", "update", "control-tower/users/admin-1", "allowed", "cor-user")
	if err := storage.DeleteUser(ctx, "admin-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.GetUser(ctx, "admin-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user lookup error = %v", err)
	}
	var auditCount int
	if err := storage.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE actor_id='admin-2'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit count after deleting actor = %d", auditCount)
	}
}

func TestUserPasswordChangeAndDisableRevokeSessions(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	user := User{
		ID: "user-1", Username: "operator", PasswordHash: "old-hash",
		Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateSession(ctx, "session-1", user.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	user.UpdatedAt = now.Add(time.Minute)
	if err := storage.UpdateUser(ctx, user, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.SessionUser(ctx, "session-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("password change did not revoke session: %v", err)
	}
	if err := storage.CreateSession(ctx, "session-2", user.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	user.Enabled = false
	user.UpdatedAt = now.Add(2 * time.Minute)
	if err := storage.UpdateUser(ctx, user, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.SessionUser(ctx, "session-2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabling user did not revoke session: %v", err)
	}
}

func TestServiceAccountTokensAreIndependentlyRevocableAndExpire(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	account := ServiceAccount{
		ID: "svc-1", Name: "backup-agent", Description: "Nightly backup",
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	active := ServiceAccountToken{
		ID: "token-1", ServiceAccountID: account.ID, Name: "primary",
		TokenHash: "active-digest", CreatedAt: now,
	}
	expiredAt := now.Add(-time.Minute)
	expired := ServiceAccountToken{
		ID: "token-2", ServiceAccountID: account.ID, Name: "expired",
		TokenHash: "expired-digest", ExpiresAt: &expiredAt, CreatedAt: now,
	}
	if err := storage.CreateServiceAccountToken(ctx, active, false); err != nil {
		t.Fatal(err)
	}
	if err := storage.CreateServiceAccountToken(ctx, expired, false); err != nil {
		t.Fatal(err)
	}
	authenticated, usedToken, err := storage.AuthenticateServiceAccount(ctx, active.TokenHash)
	if err != nil || authenticated.ID != account.ID || usedToken.LastUsedAt == nil {
		t.Fatalf("account=%+v token=%+v err=%v", authenticated, usedToken, err)
	}
	if _, _, err := storage.AuthenticateServiceAccount(ctx, expired.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token authentication error = %v", err)
	}
	if err := storage.RevokeServiceAccountToken(ctx, account.ID, active.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := storage.AuthenticateServiceAccount(ctx, active.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token authentication error = %v", err)
	}
}

func TestDisablingServiceAccountImmediatelyBlocksEveryToken(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	account := ServiceAccount{
		ID: "svc-1", Name: "media-agent", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	token := ServiceAccountToken{
		ID: "token-1", ServiceAccountID: account.ID, Name: "primary",
		TokenHash: "digest", CreatedAt: now,
	}
	if err := storage.CreateServiceAccountToken(ctx, token, false); err != nil {
		t.Fatal(err)
	}
	account.Enabled = false
	account.UpdatedAt = now.Add(time.Minute)
	if err := storage.UpdateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if _, _, err := storage.AuthenticateServiceAccount(ctx, token.TokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled account authentication error = %v", err)
	}
}

func TestServiceAccountAuditPreservesActorTypeAfterDeletion(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	account := ServiceAccount{
		ID: "svc-1", Name: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	storage.AuditActor(ctx, account.ID, "service_account", "get", "nodes/node-1/jobs", "allowed", "cor-svc")
	if err := storage.DeleteServiceAccount(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	var actorID, actorType string
	if err := storage.db.QueryRowContext(ctx, `SELECT actor_id,actor_type FROM audit_events WHERE correlation_id='cor-svc'`).
		Scan(&actorID, &actorType); err != nil {
		t.Fatal(err)
	}
	if actorID != account.ID || actorType != "service_account" {
		t.Fatalf("actor_id=%q actor_type=%q", actorID, actorType)
	}
}

func TestPolicyPersistenceAssignmentsAndCascade(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	account := ServiceAccount{
		ID: "svc-1", Name: "reader-agent", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	policy := Policy{
		ID: "policy-1", Name: "media-read", Description: "Read media",
		Rules: []rbac.Rule{
			{Path: "nodes/node-a", Capabilities: []string{"list"}},
			{Path: "nodes/node-a/files/mounts/media", Capabilities: []string{"read", "list"}},
		},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetSubjectPolicies(ctx, "service_account", account.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	loaded, err := storage.RBACPoliciesForSubject(ctx, "service_account", account.ID)
	if err != nil || len(loaded) != 1 || len(loaded[0].Rules) != 2 {
		t.Fatalf("policies=%+v err=%v", loaded, err)
	}
	if err := storage.DeletePolicy(ctx, policy.ID); err != nil {
		t.Fatal(err)
	}
	ids, err := storage.SubjectPolicyIDs(ctx, "service_account", account.ID)
	if err != nil || len(ids) != 0 {
		t.Fatalf("assignments survived policy deletion: ids=%v err=%v", ids, err)
	}
}

func TestUserRoleInheritsPoliciesAndCascadesAssignments(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	user := User{
		ID: "user-1", Username: "media-reader", PasswordHash: "hash",
		Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	policy := Policy{
		ID: "policy-1", Name: "media-read", CreatedAt: now, UpdatedAt: now,
		Rules: []rbac.Rule{{Path: "nodes/node-a/files/mounts/media", Capabilities: []string{"read", "list"}}},
	}
	if err := storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	role := Role{
		ID: "role-1", Name: "media-readers", PolicyIDs: []string{policy.ID},
		CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.CreateRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetUserRoles(ctx, user.ID, []string{role.ID, role.ID}); err != nil {
		t.Fatal(err)
	}
	roleIDs, err := storage.UserRoleIDs(ctx, user.ID)
	if err != nil || len(roleIDs) != 1 || roleIDs[0] != role.ID {
		t.Fatalf("role IDs=%v err=%v", roleIDs, err)
	}
	policies, err := storage.RBACPoliciesForSubject(ctx, "user", user.ID)
	if err != nil || len(policies) != 1 || policies[0].ID != policy.ID {
		t.Fatalf("inherited policies=%+v err=%v", policies, err)
	}
	if err := storage.SetSubjectPolicies(ctx, "user", user.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	policies, err = storage.RBACPoliciesForSubject(ctx, "user", user.ID)
	if err != nil || len(policies) != 1 {
		t.Fatalf("direct and inherited policy was not deduplicated: policies=%+v err=%v", policies, err)
	}
	if err := storage.DeleteRole(ctx, role.ID); err != nil {
		t.Fatal(err)
	}
	roleIDs, err = storage.UserRoleIDs(ctx, user.ID)
	if err != nil || len(roleIDs) != 0 {
		t.Fatalf("role assignments survived role deletion: ids=%v err=%v", roleIDs, err)
	}
}

func TestAuditDecisionPersistsEvaluatedPolicyContext(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	storage.AuditDecision(ctx, "svc-1", "service_account", "authorize", "nodes/node-a/transfers",
		"denied", "cor-rbac", []string{"deny-policy"}, "nodes/node-a/transfers", "execute")
	var policies, path, capability string
	if err := storage.db.QueryRowContext(ctx, `SELECT policy_ids,evaluated_path,capability FROM audit_events WHERE correlation_id='cor-rbac'`).
		Scan(&policies, &path, &capability); err != nil {
		t.Fatal(err)
	}
	if policies != `["deny-policy"]` || path != "nodes/node-a/transfers" || capability != "execute" {
		t.Fatalf("policies=%q path=%q capability=%q", policies, path, capability)
	}
}

func TestEmergencyRecoverAdminPromotesUserRevokesAllSessionsAndAudits(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, user := range []User{
		{ID: "admin-1", Username: "admin", PasswordHash: "old-admin", Role: "admin", Enabled: true, CreatedAt: now, UpdatedAt: now},
		{ID: "operator-1", Username: "recover.me", PasswordHash: "old-operator", Role: "operator", Enabled: false, CreatedAt: now, UpdatedAt: now},
	} {
		if err := storage.CreateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
		if err := storage.CreateSession(ctx, "session-"+user.ID, user.ID, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	newHash, err := security.HashPassword("new-emergency-password")
	if err != nil {
		t.Fatal(err)
	}
	result, err := storage.EmergencyRecoverAdmin(ctx, "unused", "recover.me", newHash, "cor-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if result.Created || result.RevokedSessions != 2 || result.User.Role != "admin" || !result.User.Enabled ||
		result.User.PasswordHash != "" {
		t.Fatalf("unexpected recovery result: %+v", result)
	}
	recovered, err := storage.UserByUsername(ctx, "recover.me")
	if err != nil || !security.VerifyPassword(recovered.PasswordHash, "new-emergency-password") {
		t.Fatalf("recovered user/password invalid: user=%+v err=%v", recovered, err)
	}
	if _, err := storage.SessionUser(ctx, "session-admin-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("admin session survived recovery: %v", err)
	}
	if _, err := storage.SessionUser(ctx, "session-operator-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("operator session survived recovery: %v", err)
	}
	var eventCount int
	if err := storage.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events
WHERE actor_type='recovery' AND action='recover_admin' AND correlation_id='cor-recovery'`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("recovery audit count=%d, want 1", eventCount)
	}
}

func TestEmergencyRecoverAdminCreatesMissingAdministrator(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	hash, err := security.HashPassword("new-emergency-password")
	if err != nil {
		t.Fatal(err)
	}
	result, err := storage.EmergencyRecoverAdmin(context.Background(), "recovery-admin", "new.admin", hash, "cor-create")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.User.ID != "recovery-admin" || result.User.Role != "admin" || !result.User.Enabled {
		t.Fatalf("unexpected created administrator: %+v", result)
	}
}

func TestEmergencyReplaceNodeTokenIsExactAndAudited(t *testing.T) {
	storage, err := Open(filepath.Join(t.TempDir(), "control.db"), testDatabaseKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	seen := now.Add(-time.Minute)
	node := Node{
		ID: "node-a", Name: "Node A", Endpoint: "https://node-a.example.test",
		TokenEncrypted: "old-encrypted", State: "online", LastSeenAt: &seen,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := storage.SaveNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	recovered, err := storage.EmergencyReplaceNodeToken(ctx, node.ID, "new-encrypted", "cor-node-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.ID != node.ID || recovered.TokenEncrypted != "" || recovered.State != "unknown" ||
		recovered.LastSeenAt != nil {
		t.Fatalf("unexpected recovered node: %+v", recovered)
	}
	persisted, err := storage.GetNode(ctx, node.ID)
	if err != nil || persisted.TokenEncrypted != "new-encrypted" || persisted.State != "unknown" ||
		persisted.LastSeenAt != nil {
		t.Fatalf("unexpected persisted node: %+v err=%v", persisted, err)
	}
	var eventCount int
	if err := storage.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events
WHERE actor_type='recovery' AND action='recover_node_token' AND correlation_id='cor-node-recovery'`).
		Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("recovery audit count=%d, want 1", eventCount)
	}
	if _, err := storage.EmergencyReplaceNodeToken(ctx, "missing", "encrypted", "cor-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing node recovery error=%v, want ErrNotFound", err)
	}
}
