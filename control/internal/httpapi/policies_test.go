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

func TestPoliciesCanBeFoundByExactName(t *testing.T) {
	h := newTypedHarness(t, false, nil)
	ids := map[string]string{}
	for _, policy := range []map[string]any{
		{"name": "media", "description": "", "rules": []map[string]any{{"path": "nodes/n1", "capabilities": []string{"read"}}}},
		{"name": "media-extra", "description": "more media", "rules": []map[string]any{{"path": "nodes/n1", "capabilities": []string{"read"}}}},
	} {
		w := h.do("admin", http.MethodPost, "/api/v1/control-tower/policies", policy)
		if w.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", w.Code, w.Body)
		}
		var created store.Policy
		if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		ids[created.Name] = created.ID
	}
	for query, want := range map[string][]string{
		"name=media":         {ids["media"]},
		"name=media-extra":   {ids["media-extra"]},
		"name=Media":         {},
		"name=med":           {},
		"name=media&q=extra": {ids["media"]},
	} {
		w := h.do("admin", http.MethodGet, "/api/v1/control-tower/policies?"+query, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", query, w.Code, w.Body)
		}
		var page struct {
			Items []store.Policy `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, policy := range page.Items {
			got = append(got, policy.ID)
			if len(policy.Rules) != 1 {
				t.Errorf("%s: policy without its rules: %+v", query, policy)
			}
		}
		if len(got) != len(want) || len(want) == 1 && got[0] != want[0] {
			t.Errorf("%s: got %v, want %v", query, got, want)
		}
	}
	if w := h.do("operator", http.MethodGet, "/api/v1/control-tower/policies?name=media", nil); w.Code != http.StatusForbidden {
		t.Fatalf("operator lookup: %d %s", w.Code, w.Body)
	}
}
