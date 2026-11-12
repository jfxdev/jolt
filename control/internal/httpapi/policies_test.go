package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jfxdev/jolt/control/internal/store"
)

func TestPolicyCanBeReadByID(t *testing.T) {
	h := newTypedHarness(t, false, nil)
	created := h.do("admin", http.MethodPost, "/api/v1/control-tower/policies", map[string]any{
		"name": "read-me", "description": "one policy",
		"rules": []map[string]any{{"path": "/nodes/n1/files/mounts/m/**", "capabilities": []string{"READ", "list"}}},
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	var want store.Policy
	if err := json.Unmarshal(created.Body.Bytes(), &want); err != nil {
		t.Fatal(err)
	}

	w := h.do("admin", http.MethodGet, "/api/v1/control-tower/policies/"+want.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}
	var got store.Policy
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Name != "read-me" || got.Description != "one policy" || len(got.Rules) != 1 {
		t.Fatalf("unexpected policy: %+v", got)
	}
	if rule := got.Rules[0]; rule.Path != "nodes/n1/files/mounts/m/**" || len(rule.Capabilities) != 2 || rule.Capabilities[0] != "read" {
		t.Fatalf("policy was not returned as stored: %+v", rule)
	}

	if w := h.do("admin", http.MethodGet, "/api/v1/control-tower/policies/missing", nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing policy: %d %s", w.Code, w.Body)
	}
	if w := h.do("operator", http.MethodGet, "/api/v1/control-tower/policies/"+want.ID, nil); w.Code != http.StatusForbidden {
		t.Fatalf("operator read: %d %s", w.Code, w.Body)
	}
}
