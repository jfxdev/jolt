package httpapi

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

func TestSignedLocalJobLeaseUsesCurrentPoliciesAndCredential(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	operator := store.User{ID: "operator", Username: "operator", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := f.storage.CreateUser(ctx, operator); err != nil {
		t.Fatal(err)
	}
	const session = "job-test-session"
	if err := f.storage.CreateSession(ctx, security.Digest(session), operator.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	base := "nodes/n1/files/mounts/m"
	policy := store.Policy{ID: "job-policy", Name: "job-policy", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/n1/jobs/**", Capabilities: []string{"execute"}},
		{Path: base + "/**", Capabilities: []string{"read", "list", "create", "update", "delete"}},
	}}
	if err := f.storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetSubjectPolicies(ctx, "user", operator.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var request *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest("GET", "/", session, nil))
	if request == nil {
		t.Fatal("session was not authenticated")
	}
	job := signedLocalJob{ID: "job", Type: "copy_local", MountID: "m", Source: "source", Destination: "folder/destination"}
	token, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	expected := signedauth.Binding{ActorID: operator.ID, CredentialID: "session-" + security.Digest("jolt-signed-session:"+session), Operation: job.Type, SourceNodeID: "n1", SourceMountID: "m", SourceRoot: job.Source, DestinationNodeID: "n1", DestinationMountID: "m", DestinationRoot: job.Destination, PlanID: job.ID, JobOptionsDigest: job.optionsDigest()}
	keys := map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}
	claims, filter, err := signedauth.VerifyJobLease(token, keys, expected, "n1", 1, now)
	if err != nil || claims.ExpiresAt != now.Add(30*time.Second).Unix() || !filter.Evaluate(base+"/source", "read", "file").Allowed || !filter.Evaluate(base+"/folder/destination", "create", "file").Allowed {
		t.Fatalf("claims=%+v filter=%v err=%v", claims, filter, err)
	}
	if _, _, err := signedauth.VerifyJobLease(token, keys, expected, "n1", 2, now); err == nil {
		t.Fatal("old revision accepted")
	}
	grant, err := f.storage.GrantTemporaryPolicy(ctx, "user", operator.ID, "wide", "admin", "user", "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	token, err = s.issueSignedLocalJobLease(request, "n1", job, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err = signedauth.VerifyJobLease(token, keys, expected, "n1", 2, now)
	if err != nil || claims.ExpiresAt != grant.ExpiresAt.Unix() {
		t.Fatalf("temporary deadline=%d want=%d err=%v", claims.ExpiresAt, grant.ExpiresAt.Unix(), err)
	}
	if err := f.storage.RevokeTemporaryPolicy(ctx, "user", operator.ID, "wide", "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	policy.Rules[1].Capabilities = []string{"read", "list", "create"}
	if err := f.storage.UpdatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 3, now); err == nil {
		t.Fatal("missing update permission accepted")
	}
	if err := f.storage.DeleteSession(ctx, security.Digest(session)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 3, now); err == nil {
		t.Fatal("revoked session accepted")
	}
}

func TestSignedLocalJobLeaseRejectsAgentsAndInvalidTargets(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	now := time.Now().UTC().Truncate(time.Second)
	ctx := context.WithValue(context.Background(), userKey, store.User{ID: f.accountID, Role: "service_account", Enabled: true})
	ctx = context.WithValue(ctx, actorTypeKey, "service_account")
	ctx = context.WithValue(ctx, credentialKey, "token-"+f.tokenID)
	ctx = context.WithValue(ctx, credentialDigestKey, security.Digest(f.token))
	ctx = context.WithValue(ctx, agentKey, agentContext{limits: store.DefaultAgentLimits()})
	request := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	job := signedLocalJob{ID: "job", Type: "delete", MountID: "m", Source: "tree"}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now); err == nil {
		t.Fatal("agent authorized for destructive job")
	}
	var admin *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { admin = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest("GET", "/", f.adminSession, nil))
	for _, bad := range []signedLocalJob{{ID: "job", Type: "delete", MountID: "m", Source: "../escape"}, {ID: "job", Type: "move_local", MountID: "m", Source: "source", Destination: "/absolute"}, {ID: "job", Type: "transfer_pull", MountID: "m", Source: "source", Destination: "dest"}} {
		if _, err := s.issueSignedLocalJobLease(admin, "n1", bad, 1, now); err == nil {
			t.Fatalf("invalid job accepted: %+v", bad)
		}
	}
}

func TestSignedJobLeaseRespectsOverwriteAndTreeDenials(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	operator := store.User{ID: "operator", Username: "operator", PasswordHash: "unused", Role: "operator", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := f.storage.CreateUser(ctx, operator); err != nil {
		t.Fatal(err)
	}
	const session = "move-test-session"
	if err := f.storage.CreateSession(ctx, security.Digest(session), operator.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	base := "nodes/n1/files/mounts/m"
	policy := store.Policy{ID: "move-policy", Name: "move-policy", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: "nodes/n1/jobs/**", Capabilities: []string{"execute"}},
		{Path: base + "/source/**", Capabilities: []string{"read", "update"}},
		{Path: base + "/destination/**", Capabilities: []string{"create"}},
	}}
	if err := f.storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetSubjectPolicies(ctx, "user", operator.ID, []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var request *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), authenticatedRequest("GET", "/", session, nil))
	job := signedLocalJob{ID: "job", Type: "move_local", MountID: "m", Source: "source", Destination: "destination/file"}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now); err == nil {
		t.Fatal("move without destination update accepted before options are bound")
	}
	job.Overwrite = true
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now); err == nil {
		t.Fatal("overwrite without update accepted")
	}
	policy.Rules[2].Capabilities = []string{"create", "update"}
	if err := f.storage.UpdatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now); err != nil {
		t.Fatalf("move with destination update rejected: %v", err)
	}
	job.Overwrite = false
	policy.Rules = append(policy.Rules, rbac.Rule{Path: base + "/source/private/**", Capabilities: []string{"deny"}})
	if err := f.storage.UpdatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now); err == nil {
		t.Fatal("tree with path denial accepted")
	}
}

func TestSignedJobLeaseRechecksServiceAccountAndGroup(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	account := store.ServiceAccount{ID: "automation", Name: "automation", Kind: "automation", Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := f.storage.CreateServiceAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetServiceAccountGroups(ctx, account.ID, []string{"group"}); err != nil {
		t.Fatal(err)
	}
	jobPolicy := store.Policy{ID: "execute", Name: "execute", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n1/jobs/**", Capabilities: []string{"execute"}}}}
	if err := f.storage.CreatePolicy(ctx, jobPolicy); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetAccessGroupPolicies(ctx, "group", []string{"wide", "execute"}); err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(12 * time.Second)
	credential := store.ServiceAccountToken{ID: "automation-token", ServiceAccountID: account.ID, Name: "credential", TokenHash: security.Digest("automation-secret"), ExpiresAt: &deadline, CreatedAt: now}
	if err := f.storage.CreateServiceAccountToken(ctx, credential, false); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: key}}
	var request *http.Request
	s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { request = r })).ServeHTTP(httptest.NewRecorder(), func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer automation-secret")
		return r
	}())
	if request == nil {
		t.Fatal("automation not authenticated")
	}
	job := signedLocalJob{ID: "job", Type: "delete", MountID: "m", Source: "tree"}
	token, err := s.issueSignedLocalJobLease(request, "n1", job, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	binding := signedauth.Binding{ActorID: account.ID, CredentialID: "token-" + credential.ID, Operation: "delete", SourceNodeID: "n1", SourceMountID: "m", SourceRoot: "tree", PlanID: "job", JobOptionsDigest: job.optionsDigest()}
	claims, _, err := signedauth.VerifyJobLease(token, map[string]ed25519.PublicKey{"key": key.Public().(ed25519.PublicKey)}, binding, "n1", 1, now)
	if err != nil || claims.ExpiresAt != deadline.Unix() {
		t.Fatalf("credential deadline=%d want=%d err=%v", claims.ExpiresAt, deadline.Unix(), err)
	}
	if err := f.storage.SetAccessGroupNodes(ctx, "group", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 2, now); err == nil {
		t.Fatal("removed node group accepted")
	}
	if err := f.storage.SetAccessGroupNodes(ctx, "group", []string{"n1"}); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.RevokeServiceAccountToken(ctx, account.ID, credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalJobLease(request, "n1", job, 2, now); err == nil {
		t.Fatal("revoked credential accepted")
	}
}
