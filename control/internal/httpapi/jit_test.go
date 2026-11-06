package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/signedauth"
	"github.com/jfxdev/jolt/control/internal/store"
)

// A node that keeps answering until the caller's context is done, or three
// seconds pass: how long a stream runs for whoever asked.
func slowNodeHarness(t *testing.T, rules []rbac.Rule, grantPermanent bool) *typedHarness {
	t.Helper()
	h := newTypedHarness(t, false, func(r *http.Request) (int, http.Header, string) {
		header := make(http.Header)
		header.Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/node" {
			return 200, header, `{"node_id":"n1","capabilities":[]}`
		}
		select {
		case <-r.Context().Done():
			return 504, header, `{}`
		case <-time.After(3 * time.Second):
			return 200, header, `{"done":true}`
		}
	}, func(cfg *config.Config) {
		cfg.SignedLocalReads, cfg.SignedUploads, cfg.SignedLocalJobs = false, false, false
	})
	now := time.Now().UTC()
	policy := store.Policy{ID: "docs", Name: "docs", CreatedAt: now, UpdatedAt: now, Rules: rules}
	if err := h.storage.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if grantPermanent {
		if err := h.storage.SetSubjectPolicies(context.Background(), "user", "operator", []string{policy.ID}); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestAStreamEndsWithTheTemporaryGrantItRestsOn(t *testing.T) {
	rules := []rbac.Rule{{Path: approvalMount + "/**", Capabilities: []string{"read", "list"}}}
	h := slowNodeHarness(t, rules, false)
	if _, err := h.storage.GrantTemporaryPolicy(context.Background(), "user", "operator", "docs", "admin", "user", "", time.Second); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	w := h.do("operator", http.MethodGet, "/api/v1/nodes/n1/mounts/m/files/content?path=a.txt", nil)
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond || w.Code == http.StatusOK {
		t.Fatalf("the stream outlived the grant: %v status %d", elapsed, w.Code)
	}
}

func TestAStreamIsNotCutWhenSomethingPermanentAlsoGrantsIt(t *testing.T) {
	rules := []rbac.Rule{{Path: approvalMount + "/**", Capabilities: []string{"read", "list"}}}
	h := slowNodeHarness(t, rules, true)
	now := time.Now().UTC()
	// A second policy gives the same access for a second only.
	if err := h.storage.CreatePolicy(context.Background(), store.Policy{ID: "brief", Name: "brief", CreatedAt: now, UpdatedAt: now, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.storage.GrantTemporaryPolicy(context.Background(), "user", "operator", "brief", "admin", "user", "", time.Second); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	w := h.do("operator", http.MethodGet, "/api/v1/nodes/n1/mounts/m/files/content?path=a.txt", nil)
	if elapsed := time.Since(started); elapsed < 2500*time.Millisecond || w.Code != http.StatusOK {
		t.Fatalf("a permanent grant was cut by a temporary one: %v status %d", elapsed, w.Code)
	}
}

func TestAdministratorsAreNotBoundByTemporaryGrants(t *testing.T) {
	h := slowNodeHarness(t, []rbac.Rule{{Path: approvalMount + "/**", Capabilities: []string{"read"}}}, false)
	if _, err := h.storage.GrantTemporaryPolicy(context.Background(), "user", "admin", "docs", "admin", "user", "", time.Second); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	w := h.do("admin", http.MethodGet, "/api/v1/nodes/n1/mounts/m/files/content?path=a.txt", nil)
	if time.Since(started) < 2500*time.Millisecond || w.Code != http.StatusOK {
		t.Fatalf("an administrator was cut: status %d", w.Code)
	}
}

func TestATransferLeaseNeverOutlivesATemporaryGrant(t *testing.T) {
	fake := &transferFake{sourceIdentity: "source", destinationCaps: transferCaps}
	handler, storage, sessions := transferApprovalHarness(t, fake)
	ctx := context.Background()
	// The operator keeps nothing permanent: the policy is a ten second grant.
	if err := storage.SetSubjectPolicies(ctx, "user", "operator", nil); err != nil {
		t.Fatal(err)
	}
	grant, err := storage.GrantTemporaryPolicy(ctx, "user", "operator", "operator-transfers", "admin", "user", "", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers", sessions["operator"], []byte(transferPayload))
	request.Header.Set("Idempotency-Key", "jit-copy")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || len(fake.createHeaders) != 1 {
		t.Fatalf("create: %d %s", response.Code, response.Body)
	}
	envelope := fake.createHeaders[0].Get(signedAuthorizationHeader)
	binding, err := signedauth.VerifiedJobLeaseBinding(envelope, fake.keys, "destination", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err := signedauth.VerifyJobLease(envelope, fake.keys, binding, "destination", 1, time.Now().UTC())
	if err != nil || claims.ExpiresAt > grant.ExpiresAt.Unix() {
		t.Fatalf("the lease outlives the grant: lease %d grant %d err %v", claims.ExpiresAt, grant.ExpiresAt.Unix(), err)
	}
	// Once the grant is revoked, nothing renews.
	if err := storage.RevokeTemporaryPolicy(ctx, "user", "operator", "operator-transfers", "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	again := authenticatedRequest(http.MethodPost, "/api/v1/nodes/destination/transfers", sessions["operator"], []byte(transferPayload))
	again.Header.Set("Idempotency-Key", "jit-copy-2")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, again)
	if denied.Code != http.StatusForbidden || len(fake.createHeaders) != 1 {
		t.Fatalf("after revocation: %d %s", denied.Code, denied.Body)
	}
}
