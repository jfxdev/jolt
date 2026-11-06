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
	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

func TestIssueSignedLocalReadUsesAuthenticatedSession(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}}
	now := time.Now().UTC().Truncate(time.Second)
	var token, issuedCredential string
	var issueErr error
	var authenticated *http.Request
	root, operation := "file.txt", "content"
	handler := s.auth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		authenticated = r
		issuedCredential, _ = r.Context().Value(credentialKey).(string)
		token, issueErr = s.issueSignedLocalRead(r, "n1", "m", root, operation, now)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authenticatedRequest(http.MethodGet, "/", f.adminSession, nil))
	if issueErr != nil || token == "" || issuedCredential == "" || strings.Contains(issuedCredential, f.adminSession) {
		t.Fatalf("session context: %q %v", issuedCredential, issueErr)
	}
	claims, filter, err := signedauth.VerifyLocalRead(token, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "content", "m", "file.txt", now)
	if err != nil || claims.Binding.ActorID != "admin" || claims.Binding.CredentialID != issuedCredential || claims.ExpiresAt-claims.IssuedAt != 30 {
		t.Fatalf("claims=%+v error=%v", claims, err)
	}
	if !filter.Evaluate("nodes/n1/files/mounts/m/file.txt", "read", "file").Allowed {
		t.Fatal("admin read was not included")
	}
	sessionExpiry := now.Add(10 * time.Second)
	if err := f.storage.CreateSession(context.Background(), security.Digest("short-browser-session"), "admin", sessionExpiry); err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), authenticatedRequest(http.MethodGet, "/", "short-browser-session", nil))
	if issueErr != nil {
		t.Fatal(issueErr)
	}
	shortClaims, _, err := signedauth.VerifyLocalRead(token, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "content", "m", "file.txt", now)
	if err != nil || shortClaims.ExpiresAt != sessionExpiry.Unix() {
		t.Fatalf("session expiry: %+v %v", shortClaims, err)
	}
	policy := store.Policy{ID: "admin-typed", Name: "admin-typed", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n1/files/mounts/m/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}}}
	if err := f.storage.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetSubjectPolicies(context.Background(), "user", "admin", []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	root, operation = "secret.pem", "metadata"
	handler.ServeHTTP(httptest.NewRecorder(), authenticatedRequest(http.MethodGet, "/", f.adminSession, nil))
	if issueErr != nil {
		t.Fatal(issueErr)
	}
	_, filter, err = signedauth.VerifyLocalRead(token, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", operation, "m", root, now)
	if err != nil {
		t.Fatal(err)
	}
	if decision := filter.Evaluate("nodes/n1/files/mounts/m/secret.pem", "read", "file"); !decision.Denied {
		t.Fatalf("admin typed denial missing: %+v", decision)
	}
	if err := f.storage.DeleteSession(context.Background(), security.Digest(f.adminSession)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(authenticated, "n1", "m", "file.txt", "content", now); err == nil {
		t.Fatal("revoked browser session from stale request context was accepted")
	}
}

func TestIssueSignedLocalReadHonorsAgentCeilingAndPolicy(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}}
	limits := store.DefaultAgentLimits()
	limits.Capabilities = &[]string{"list"}
	if err := f.storage.UpdateAgentTokenLimits(context.Background(), f.accountID, f.tokenID, limits); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), userKey, store.User{ID: f.accountID, Role: "service_account", Enabled: true})
	ctx = context.WithValue(ctx, actorTypeKey, "service_account")
	ctx = context.WithValue(ctx, groupKey, []string{"group"})
	ctx = context.WithValue(ctx, credentialKey, "token-"+f.tokenID)
	ctx = context.WithValue(ctx, credentialDigestKey, security.Digest(f.token))
	ctx = context.WithValue(ctx, agentKey, agentContext{limits: limits})
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	now := time.Now().UTC().Truncate(time.Second)
	token, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, filter, err := signedauth.VerifyLocalRead(token, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "list", "m", ".", now)
	if err != nil || claims.Binding.CredentialID != "token-"+f.tokenID {
		t.Fatalf("claims=%+v error=%v", claims, err)
	}
	if !filter.Evaluate("nodes/n1/files/mounts/m/a.txt", "list", "file").Allowed || filter.Evaluate("nodes/n1/files/mounts/m/a.txt", "read", "file").Allowed {
		t.Fatal("credential ceiling not applied to signed filter")
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", "a.txt", "content", now); err == nil {
		t.Fatal("credential ceiling bypassed")
	}
	if _, err := s.issueSignedLocalRead(r, "other", "m", ".", "list", now); err == nil {
		t.Fatal("node group scope bypassed")
	}
	for _, root := range []string{"/absolute", "../escape", "a/../b", " a", `a\\b`} {
		if _, err := s.issueSignedLocalRead(r, "n1", "m", root, "list", now); err == nil {
			t.Fatalf("invalid root accepted: %q", root)
		}
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "delete", now); err == nil {
		t.Fatal("mutation operation signed")
	}
	group, err := f.storage.GetAccessGroup(context.Background(), "group")
	if err != nil {
		t.Fatal(err)
	}
	group.Enabled = false
	if err := f.storage.UpdateAccessGroup(context.Background(), group); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", now); err == nil {
		t.Fatal("disabled group from stale request context was accepted")
	}
	group.Enabled = true
	if err := f.storage.UpdateAccessGroup(context.Background(), group); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.RevokeServiceAccountToken(context.Background(), f.accountID, f.tokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", now); err == nil {
		t.Fatal("revoked credential from stale request context was accepted")
	}
}

func TestIssueSignedLocalReadUsesCurrentTypedPoliciesAndDeadline(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	now := time.Now().UTC().Truncate(time.Second)
	policy := store.Policy{ID: "typed", Name: "typed", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n1/files/mounts/m/**", Capabilities: []string{"DENY", "READ"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}}}
	if err := f.storage.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetAccessGroupPolicies(context.Background(), "group", []string{"wide", "typed"}); err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(10*time.Second))
	defer cancel()
	ctx = context.WithValue(ctx, userKey, store.User{ID: f.accountID, Role: "service_account", Enabled: true})
	ctx = context.WithValue(ctx, actorTypeKey, "service_account")
	ctx = context.WithValue(ctx, groupKey, []string{"group"})
	ctx = context.WithValue(ctx, credentialKey, "token-"+f.tokenID)
	ctx = context.WithValue(ctx, credentialDigestKey, security.Digest(f.token))
	ctx = context.WithValue(ctx, agentKey, agentContext{limits: store.DefaultAgentLimits()})
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	token, err := s.issueSignedLocalRead(r, "n1", "m", "secret.pem", "metadata", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, filter, err := signedauth.VerifyLocalRead(token, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "metadata", "m", "secret.pem", now)
	if err != nil || claims.ExpiresAt != now.Add(10*time.Second).Unix() {
		t.Fatalf("deadline: %+v %v", claims, err)
	}
	if decision := filter.Evaluate("nodes/n1/files/mounts/m/secret.pem", "read", "file"); !decision.Denied || decision.Visibility != "hidden" {
		t.Fatalf("typed denial missing: %+v", decision)
	}
	content, err := s.issueSignedLocalRead(r, "n1", "m", "secret.pem", "content", now)
	if err != nil {
		t.Fatalf("node must decide actual entry type: %v", err)
	}
	_, contentFilter, err := signedauth.VerifyLocalRead(content, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "content", "m", "secret.pem", now)
	if err != nil || !contentFilter.Evaluate("nodes/n1/files/mounts/m/secret.pem", "read", "file").Denied {
		t.Fatalf("content typed denial missing: %v", err)
	}
	archive, err := s.issueSignedLocalRead(r, "n1", "m", ".", "archive", now)
	if err != nil {
		t.Fatalf("typed denial should be delegated to node: %v", err)
	}
	_, archiveFilter, err := signedauth.VerifyLocalRead(archive, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "archive", "m", ".", now)
	if err != nil || !archiveFilter.Evaluate("nodes/n1/files/mounts/m/secret.pem", "read", "file").Denied {
		t.Fatalf("archive typed denial: %v", err)
	}
	pathDeny := store.Policy{ID: "path-deny", Name: "path-deny", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n1/files/mounts/m/private/**", Capabilities: []string{"deny"}}}}
	if err := f.storage.CreatePolicy(context.Background(), pathDeny); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetAccessGroupPolicies(context.Background(), "group", []string{"wide", "typed", "path-deny"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "archive", now); err == nil {
		t.Fatal("path denial inside tree was not refused")
	}
}

func TestIssueSignedLocalReadBoundsCredentialExpiryAndReloadsLimits(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), client)
	now := time.Now().UTC().Truncate(time.Second)
	expiry := now.Add(10 * time.Second)
	limits := store.DefaultAgentLimits()
	credential := store.ServiceAccountToken{ID: "short", ServiceAccountID: f.accountID, Name: "short", TokenHash: security.Digest("synthetic-short-token"), ExpiresAt: &expiry, CreatedAt: now, AgentLimits: &limits}
	if err := f.storage.CreateServiceAccountToken(context.Background(), credential, false); err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}}
	ctx := context.WithValue(context.Background(), userKey, store.User{ID: f.accountID, Role: "service_account", Enabled: true})
	ctx = context.WithValue(ctx, actorTypeKey, "service_account")
	ctx = context.WithValue(ctx, credentialKey, "token-short")
	ctx = context.WithValue(ctx, credentialDigestKey, security.Digest("synthetic-short-token"))
	ctx = context.WithValue(ctx, agentKey, agentContext{limits: limits})
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	token, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", now)
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err := signedauth.VerifyLocalRead(token, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "list", "m", ".", now)
	if err != nil || claims.ExpiresAt != expiry.Unix() {
		t.Fatalf("credential expiry: %+v %v", claims, err)
	}
	limits.Capabilities = &[]string{}
	if err := f.storage.UpdateAgentTokenLimits(context.Background(), f.accountID, credential.ID, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", now); err == nil {
		t.Fatal("stale agent limits were accepted")
	}
	limits.Capabilities = &[]string{"list"}
	limits.AllowedCIDRs = []string{"10.0.0.0/8"}
	if err := f.storage.UpdateAgentTokenLimits(context.Background(), f.accountID, credential.ID, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", now); err == nil {
		t.Fatal("changed CIDR was ignored")
	}
	r.RemoteAddr = "10.1.2.3:1234"
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", now); err != nil {
		t.Fatalf("allowed CIDR rejected: %v", err)
	}
}
