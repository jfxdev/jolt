package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/store"
)

func TestTypeRulesAreRejectedUntilNodeFilteringIsAvailable(t *testing.T) {
	handler, storage, session := testUserHandler(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true})
	now := time.Now().UTC()
	policy := store.Policy{ID: "existing", Name: "existing", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n/files/mounts/m/**", Capabilities: []string{"read"}}}}
	if err := storage.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, route, body string }{
		{http.MethodPost, "/api/v1/control-tower/policies", `{"name":"bad","rules":[{"path":"nodes/n/files/mounts/m/**","capabilities":["read"],"file_types":{"extensions":["txt"]}}]}`},
		{http.MethodPatch, "/api/v1/control-tower/policies/existing", `{"name":"existing","rules":[{"path":"nodes/n/files/mounts/m/**","capabilities":["read"],"visibility":"visible"}]}`},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, authenticatedRequest(tc.method, tc.route, session, []byte(tc.body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("unsupported rule was accepted: %d %s", w.Code, w.Body.String())
		}
	}
	current, err := storage.GetPolicy(context.Background(), policy.ID)
	if err != nil || len(current.Rules) != 1 || current.Rules[0].Capabilities[0] != "read" {
		t.Fatalf("existing policy changed: %+v %v", current, err)
	}
}

func TestPendingTypePolicyCannotBeReplacedThroughLegacyEditor(t *testing.T) {
	handler, storage, session := testUserHandler(t, store.User{ID: "admin", Username: "admin", Role: "admin", Enabled: true})
	now := time.Now().UTC()
	policy := store.Policy{ID: "typed", Name: "typed", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{{Path: "nodes/n/files/mounts/m/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}}}
	if err := storage.CreatePolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	body := []byte(`{"name":"typed","rules":[{"path":"nodes/n/files/mounts/m/**","capabilities":["read"]}]}`)
	handler.ServeHTTP(w, authenticatedRequest(http.MethodPatch, "/api/v1/control-tower/policies/typed", session, body))
	if w.Code != http.StatusConflict {
		t.Fatalf("legacy replacement: %d %s", w.Code, w.Body)
	}
	stored, err := storage.GetPolicy(context.Background(), policy.ID)
	if err != nil || len(stored.Rules) != 1 || stored.Rules[0].FileTypes == nil {
		t.Fatalf("type policy changed: %+v %v", stored, err)
	}
}
