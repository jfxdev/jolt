package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/security"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
	"github.com/jfxdev/jolt/control/internal/workload"
)

func TestFederatedAgentAuthenticationAndPersistentLimits(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bundle) }))
	defer issuer.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	definitions := map[string]any{"version": 1, "providers": []any{
		map[string]any{"id": "oidc", "type": "jwt", "issuer": "issuer", "audience": "jolt", "jwks_url": issuer.URL, "algorithms": []string{"RS256"}},
		map[string]any{"id": "spire", "type": "jwt_svid", "trust_domain": "example.org", "audience": "svid-aud", "bundle_file": "bundle.json"},
	}}
	data, _ := json.Marshal(definitions)
	file := filepath.Join(dir, "providers.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := workload.LoadProviders(file)
	if err != nil {
		t.Fatal(err)
	}
	streamStarted := make(chan struct{}, 1)
	streamCancelled := make(chan struct{}, 1)
	node := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("block") == "true" {
			streamStarted <- struct{}{}
			<-r.Context().Done()
			streamCancelled <- struct{}{}
			return nil, r.Context().Err()
		}
		body := `{"items":[]}`
		if r.Header.Get("X-Jolt-Capability-Check") == "agent-secret-scan" {
			body = `{"node_id":"n1","capabilities":["agent_secret_scan_v1"]}`
		}
		h := make(http.Header)
		h.Set("Content-Type", "application/json")
		h.Set("X-Jolt-Scan-Applied", "secrets")
		return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}, nil
	})}
	f := setupAgent(t, store.DefaultAgentLimits(), node)
	handler := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), WorkloadProviders: providers}, f.storage, slog.New(slog.NewTextHandler(io.Discard, nil)), node)
	ctx := context.Background()
	limits := store.DefaultAgentLimits()
	limits.Burst, limits.RequestsPerMinute = 2, 1
	for _, identity := range []store.WorkloadIdentity{
		{CredentialID: "federated", ServiceAccountID: f.accountID, ProviderID: "oidc", Issuer: "issuer", Subject: "agent", Audience: "jolt"},
		{CredentialID: "svid", ServiceAccountID: f.accountID, ProviderID: "spire", Subject: "spiffe://example.org/agent", Audience: "svid-aud"},
	} {
		if err := f.storage.CreateWorkloadIdentity(ctx, identity, &limits, "admin", "user", ""); err != nil {
			t.Fatal(err)
		}
	}
	sign := func(private *rsa.PrivateKey, claims jwt.Claims) string {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: private}, (&jose.SignerOptions{}).WithHeader("kid", "key").WithType("JWT"))
		if err != nil {
			t.Fatal(err)
		}
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	call := func(method, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v1/nodes/n1/mounts/m/files", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	now := time.Now()
	claims := jwt.Claims{Issuer: "issuer", Subject: "agent", Audience: jwt.Audience{"jolt"}, Expiry: jwt.NewNumericDate(now.Add(time.Hour)), ID: "one"}
	for _, tc := range []struct {
		name   string
		claims jwt.Claims
		key    *rsa.PrivateKey
	}{
		{"bad signature", claims, other},
		{"unmapped", jwt.Claims{Issuer: "issuer", Subject: "other", Audience: jwt.Audience{"jolt"}, Expiry: claims.Expiry}, key},
		{"audience", jwt.Claims{Issuer: "issuer", Subject: "agent", Audience: jwt.Audience{"other"}, Expiry: claims.Expiry}, key},
		{"expired", jwt.Claims{Issuer: "issuer", Subject: "agent", Audience: claims.Audience, Expiry: jwt.NewNumericDate(now.Add(-time.Second))}, key},
		{"too long", jwt.Claims{Issuer: "issuer", Subject: "agent", Audience: claims.Audience, Expiry: jwt.NewNumericDate(now.Add(31 * 24 * time.Hour))}, key},
	} {
		if w := call("GET", sign(tc.key, tc.claims)); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d %s", tc.name, w.Code, w.Body)
		}
	}
	if w := call("GET", "workload:federated"); w.Code != http.StatusUnauthorized {
		t.Fatalf("synthetic bearer accepted: %d", w.Code)
	}
	if w := call("GET", sign(key, claims)); w.Code != http.StatusOK {
		t.Fatalf("JWT: %d %s", w.Code, w.Body)
	}
	day := now.UTC().Format("2006-01-02")
	used, err := f.storage.AgentUsage(ctx, "federated", day)
	if err != nil || used == 0 {
		t.Fatalf("usage=%d err=%v", used, err)
	}
	claims.ID = "two"
	if w := call("DELETE", sign(key, claims)); w.Code != http.StatusForbidden {
		t.Fatalf("write: %d %s", w.Code, w.Body)
	}
	if w := call("GET", sign(key, claims)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("rotated JWT reset rate limit: %d %s", w.Code, w.Body)
	}
	svidClaims := jwt.Claims{Subject: "spiffe://example.org/agent", Audience: jwt.Audience{"svid-aud"}, Expiry: jwt.NewNumericDate(now.Add(time.Hour))}
	if w := call("GET", sign(key, svidClaims)); w.Code != http.StatusOK {
		t.Fatalf("SVID: %d %s", w.Code, w.Body)
	}
	streamContext, stopStream := context.WithTimeout(ctx, 5*time.Second)
	defer stopStream()
	streamDone := make(chan struct{})
	streamToken := sign(key, svidClaims)
	go func() {
		defer close(streamDone)
		defer func() { _ = recover() }()
		r := httptest.NewRequest("GET", "/api/v1/nodes/n1/mounts/m/files?block=true", nil).WithContext(streamContext)
		r.Header.Set("Authorization", "Bearer "+streamToken)
		handler.ServeHTTP(httptest.NewRecorder(), r)
	}()
	select {
	case <-streamStarted:
	case <-streamContext.Done():
		t.Fatal("stream did not start")
	}
	disable := httptest.NewRecorder()
	handler.ServeHTTP(disable, authenticatedRequest("PATCH", "/api/v1/control-tower/service-accounts/"+f.accountID+"/workload-identities/svid", f.adminSession, []byte(`{"enabled":false}`)))
	if disable.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", disable.Code, disable.Body)
	}
	select {
	case <-streamCancelled:
	case <-streamContext.Done():
		t.Fatal("disabling identity did not cancel stream")
	}
	<-streamDone
	if w := call("GET", sign(key, svidClaims)); w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled SVID: %d %s", w.Code, w.Body)
	}
	nowUTC := time.Now().UTC()
	if err := f.storage.CreateServiceAccount(ctx, store.ServiceAccount{ID: "automation", Name: "automation", Kind: "automation", Enabled: true, CreatedAt: nowUTC, UpdatedAt: nowUTC}); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.SetServiceAccountGroups(ctx, "automation", []string{"group"}); err != nil {
		t.Fatal(err)
	}
	if err := f.storage.CreateWorkloadIdentity(ctx, store.WorkloadIdentity{CredentialID: "automatic", ServiceAccountID: "automation", ProviderID: "oidc", Issuer: "issuer", Subject: "automatic", Audience: "jolt"}, nil, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	claims.Subject = "automatic"
	if w := call("GET", sign(key, claims)); w.Code != http.StatusUnauthorized {
		t.Fatalf("automation workload unexpectedly enabled: %d %s", w.Code, w.Body)
	}
	shortExpiry := time.Now().UTC().Truncate(time.Second).Add(10 * time.Second)
	claims.Subject, claims.Expiry = "agent", jwt.NewNumericDate(shortExpiry)
	shortToken := sign(key, claims)
	verified, err := providers.Verify(ctx, shortToken)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	s := &Server{store: f.storage, config: config.Config{WorkloadProviders: providers, AuthorizationSigningKeyID: "key", AuthorizationSigningKey: private}}
	requestContext := context.WithValue(ctx, workloadIdentityKey, verified)
	requestContext = context.WithValue(requestContext, userKey, store.User{ID: f.accountID, Role: "service_account", Enabled: true})
	requestContext = context.WithValue(requestContext, actorTypeKey, "service_account")
	requestContext = context.WithValue(requestContext, groupKey, []string{"group"})
	requestContext = context.WithValue(requestContext, credentialKey, "token-federated")
	requestContext = context.WithValue(requestContext, credentialDigestKey, security.Digest(shortToken))
	requestContext = context.WithValue(requestContext, agentKey, agentContext{limits: limits})
	r := httptest.NewRequest("GET", "/", nil).WithContext(requestContext)
	issuedAt := time.Now().UTC().Truncate(time.Second)
	envelope, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	bound, _, err := signedauth.VerifyLocalRead(envelope, map[string]ed25519.PublicKey{"key": private.Public().(ed25519.PublicKey)}, "n1", "list", "m", ".", issuedAt)
	if err != nil || bound.Binding.CredentialID != "token-federated" || bound.ExpiresAt != shortExpiry.Unix() {
		t.Fatalf("signed workload scope or expiry: %+v, %v", bound, err)
	}
	if err := f.storage.SetWorkloadIdentityEnabled(ctx, f.accountID, "federated", false, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issueSignedLocalRead(r, "n1", "m", ".", "list", issuedAt); err == nil {
		t.Fatal("stale workload identity signed after disable")
	}
}
