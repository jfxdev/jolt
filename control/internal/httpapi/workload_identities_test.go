package httpapi

import (
	"context"
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

	"github.com/jfxdev/jolt/control/internal/config"
	"github.com/jfxdev/jolt/control/internal/metrics"
	"github.com/jfxdev/jolt/control/internal/store"
	"github.com/jfxdev/jolt/control/internal/workload"
)

func TestWorkloadIdentityAdministration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "providers.json")
	data := `{"version":1,"providers":[{"id":"issuer","type":"jwt","issuer":"https://issuer.example","audience":"jolt","jwks_url":"https://issuer.example/jwks","algorithms":["RS256"]}]}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	providers, err := workload.LoadProviders(file)
	if err != nil {
		t.Fatal(err)
	}
	_, storage, session := testUserHandler(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true})
	now := time.Now().UTC()
	for _, id := range []string{"agent", "other"} {
		if err := storage.CreateServiceAccount(context.Background(), store.ServiceAccount{ID: id, Name: id, Kind: "agent", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	handler := newHandler(config.Config{EncryptionKey: make([]byte, 32), StaticDir: t.TempDir(), WorkloadProviders: providers}, storage, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	base := "/api/v1/control-tower/service-accounts/agent/workload-identities"
	call := func(method, url, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, authenticatedRequest(method, url, session, []byte(body)))
		return w
	}
	bad := `{"provider_id":"issuer","issuer":"wrong","subject":"workload","audience":"jolt"}`
	if w := call("POST", base, bad); w.Code != http.StatusBadRequest {
		t.Fatalf("bad mapping: %d %s", w.Code, w.Body.String())
	}
	body := `{"provider_id":"issuer","issuer":"https://issuer.example","subject":"workload","audience":"jolt"}`
	created := call("POST", base, body)
	var identity store.WorkloadIdentity
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &identity) != nil || !identity.Enabled || identity.AgentLimits == nil || identity.AgentLimits.MaxConcurrent != 2 {
		t.Fatalf("creation: %d %s", created.Code, created.Body.String())
	}
	if w := call("POST", base, body); w.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d %s", w.Code, w.Body.String())
	}
	if w := call("GET", base, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), identity.CredentialID) {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	static := call("GET", "/api/v1/control-tower/service-accounts/agent/tokens", "")
	if static.Code != http.StatusOK || strings.Contains(static.Body.String(), identity.CredentialID) {
		t.Fatalf("mapping appeared as static key: %d %s", static.Code, static.Body.String())
	}
	other := "/api/v1/control-tower/service-accounts/other/workload-identities/" + identity.CredentialID
	if w := call("PATCH", other, `{"enabled":false}`); w.Code != http.StatusNotFound {
		t.Fatalf("cross-account update: %d %s", w.Code, w.Body.String())
	}
	endpoint := base + "/" + identity.CredentialID
	if w := call("PATCH", endpoint, `{"enabled":false}`); w.Code != http.StatusNoContent {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if w := call("PATCH", endpoint, `{"enabled":true}`); w.Code != http.StatusNoContent {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	if err := storage.RevokeServiceAccountToken(context.Background(), "agent", identity.CredentialID); err != nil {
		t.Fatal(err)
	}
	if w := call("PATCH", endpoint, `{"enabled":true}`); w.Code != http.StatusConflict {
		t.Fatalf("revoked enable: %d %s", w.Code, w.Body.String())
	}
	if w := call("GET", base, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"revoked":true`) {
		t.Fatalf("revocation not visible: %d %s", w.Code, w.Body.String())
	}
}

func TestDisablingWorkloadIdentityCancelsItsActiveAgentRequests(t *testing.T) {
	_, storage, _ := testUserHandler(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true})
	now := time.Now().UTC()
	if err := storage.CreateServiceAccount(context.Background(), store.ServiceAccount{ID: "agent", Name: "agent", Kind: "agent", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	identity := store.WorkloadIdentity{CredentialID: "wid", ServiceAccountID: "agent", ProviderID: "provider", Subject: "subject", Audience: "jolt"}
	if err := storage.CreateWorkloadIdentity(context.Background(), identity, nil, "admin", "user", ""); err != nil {
		t.Fatal(err)
	}
	active, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{store: storage, registry: metrics.NewRegistry(), log: slog.New(slog.NewTextHandler(io.Discard, nil)), agentTokens: map[string]*agentTokenState{
		"wid": {accountID: "agent", active: map[uint64]context.CancelFunc{1: cancel}},
	}}
	request := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{"enabled":false}`))
	request.SetPathValue("serviceAccountID", "agent")
	request.SetPathValue("credentialID", "wid")
	ctx := context.WithValue(request.Context(), userKey, store.User{ID: "admin", Role: "admin", Enabled: true})
	ctx = context.WithValue(ctx, actorTypeKey, "user")
	response := httptest.NewRecorder()
	s.updateWorkloadIdentity(response, request.WithContext(ctx))
	if response.Code != http.StatusNoContent || active.Err() == nil {
		t.Fatalf("disable=%d active=%v body=%s", response.Code, active.Err(), response.Body.String())
	}
}

func TestWorkloadIdentityAdministrationRequiresSudo(t *testing.T) {
	handler, _, session := testUserHandler(t, store.User{ID: "operator", Username: "operator", Role: "operator", Enabled: true})
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/control-tower/service-accounts/agent/workload-identities"},
		{"POST", "/api/v1/control-tower/service-accounts/agent/workload-identities"},
		{"PATCH", "/api/v1/control-tower/service-accounts/agent/workload-identities/id"},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, authenticatedRequest(tc.method, tc.path, session, []byte(`{}`)))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}
