package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/store"
)

type effectiveResponse struct {
	Subject       map[string]any `json:"subject"`
	TypedPolicies bool           `json:"typed_policies"`
	Notes         []string       `json:"notes"`
	Results       []struct {
		Path         string                         `json:"path"`
		EntryType    string                         `json:"entry_type"`
		Reason       string                         `json:"reason"`
		Capabilities map[string]effectiveCapability `json:"capabilities"`
	} `json:"results"`
}

func effectiveHarness(t *testing.T, typed bool) *typedHarness {
	t.Helper()
	h := newTypedHarness(t, typed, func(*http.Request) (int, http.Header, string) { return 404, nil, `{}` })
	ctx, now := context.Background(), time.Now().UTC()
	base := "nodes/n1/files/mounts/m"
	policy := store.Policy{ID: "typed", Name: "typed", CreatedAt: now, UpdatedAt: now, Rules: []rbac.Rule{
		{Path: base + "/**", Capabilities: []string{"read", "list", "delete"}},
		{Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}, Visibility: "visible"},
		{Path: base + "/secret/**", Capabilities: []string{"deny", "list"}, FileTypes: &filetypes.Selector{Classes: []string{"document"}}},
	}}
	if err := h.storage.CreatePolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetSubjectPolicies(ctx, "user", "operator", []string{policy.ID}); err != nil {
		t.Fatal(err)
	}
	return h
}

func askEffective(t *testing.T, h *typedHarness, user, actorType, id string, checks ...map[string]string) (*effectiveResponse, int) {
	t.Helper()
	w := h.do(user, http.MethodPost, "/api/v1/control-tower/subjects/"+actorType+"/"+id+"/effective-access", map[string]any{"checks": checks})
	var out effectiveResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err, w.Body)
		}
	}
	return &out, w.Code
}

func TestEffectiveAccessSeparatesFilesFromDirectoriesAndTellsHiddenFromBlocked(t *testing.T) {
	h := effectiveHarness(t, true)
	base := "nodes/n1/files/mounts/m"
	out, code := askEffective(t, h, "admin", "user", "operator",
		map[string]string{"path": base + "/docs/notes.txt", "entry_type": "file"},
		map[string]string{"path": base + "/docs/key.pem", "entry_type": "file"},
		map[string]string{"path": base + "/docs/key.pem", "entry_type": "directory"},
		map[string]string{"path": base + "/secret/a.pdf", "entry_type": "file"},
	)
	if code != http.StatusOK || !out.TypedPolicies || len(out.Results) != 4 {
		t.Fatalf("code=%d %+v", code, out)
	}
	want := []struct {
		capability, outcome string
		allowed             bool
	}{
		{"read", "allowed", true},   // plain file
		{"delete", "allowed", true}, // the typed denial only takes read away
		{"read", "blocked", false},  // shown, not usable: visibility=visible
		{"delete", "allowed", true},
		{"read", "allowed", true}, // a directory by that name stays navigable
		{"list", "hidden", false}, // a typed deny without visibility hides the file
	}
	got := []effectiveCapability{
		out.Results[0].Capabilities["read"], out.Results[1].Capabilities["delete"], out.Results[1].Capabilities["read"], out.Results[1].Capabilities["delete"],
		out.Results[2].Capabilities["read"], out.Results[3].Capabilities["list"],
	}
	for index, test := range want {
		if got[index].Outcome != test.outcome || got[index].Allowed != test.allowed {
			t.Fatalf("case %d (%s): %+v want %s", index, test.capability, got[index], test.outcome)
		}
	}
	if !got[2].Typed || len(got[2].PolicyIDs) != 1 || got[2].PolicyIDs[0] != "typed" {
		t.Fatalf("typed rule not attributed: %+v", got[2])
	}
	// The answer says which rules it came from, so a refusal can be traced.
	effects := map[string]bool{}
	for _, rule := range got[2].Rules {
		effects[rule.Effect] = true
	}
	if !effects["allow"] || !effects["typed_deny"] {
		t.Fatalf("rules behind a blocked read: %+v", got[2].Rules)
	}
	if len(out.Results[0].Capabilities["sudo"].Rules) != 0 {
		t.Fatalf("a capability no rule mentions listed rules: %+v", out.Results[0].Capabilities["sudo"].Rules)
	}
	if out.Results[0].Capabilities["create"].Outcome != "denied" || out.Results[0].Capabilities["sudo"].Allowed {
		t.Fatalf("an ungranted capability is allowed: %+v", out.Results[0].Capabilities)
	}
}

func TestEffectiveAccessMatchesWhatTheEvaluatorsDecide(t *testing.T) {
	h := effectiveHarness(t, true)
	policies, err := h.storage.RBACPoliciesForSubject(context.Background(), "user", "operator")
	if err != nil {
		t.Fatal(err)
	}
	policies = rbac.ExpandCompatibilityRules(policies)
	base := "nodes/n1/files/mounts/m"
	for _, path := range []string{base, base + "/a.pem", base + "/x/b.txt", base + "/secret/c.pdf", base + "/secret"} {
		for _, entryType := range []string{"file", "directory"} {
			out, code := askEffective(t, h, "admin", "user", "operator", map[string]string{"path": path, "entry_type": entryType})
			if code != http.StatusOK {
				t.Fatalf("%d", code)
			}
			for _, capability := range effectiveCapabilities {
				want := rbac.EvaluateEntry(policies, path, capability, entryType)
				if got := out.Results[0].Capabilities[capability]; got.Allowed != want.Allowed || got.Denied != want.Denied {
					t.Fatalf("%s %s %s: %+v want %+v", path, entryType, capability, got, want)
				}
				// The Control Tower's own authorization may never allow what the
				// exact answer for either kind of entry denies.
				for _, mode := range []rbac.EntryMode{rbac.EveryEntry, rbac.NodeFiltered} {
					decided := rbac.EvaluateTyped(policies, path, capability, mode)
					if mode == rbac.EveryEntry && decided.Allowed && !want.Allowed {
						t.Fatalf("%s %s %s: conservative evaluator allows what the entry is denied", path, entryType, capability)
					}
				}
			}
		}
	}
}

func TestEffectiveAccessIsForPolicyAdministratorsOnly(t *testing.T) {
	h := effectiveHarness(t, true)
	check := map[string]string{"path": "nodes/n1/files/mounts/m", "entry_type": "directory"}
	if _, code := askEffective(t, h, "operator", "user", "operator", check); code != http.StatusForbidden {
		t.Fatalf("operator code=%d", code)
	}
	for name, test := range map[string]struct {
		actor, id string
		checks    []map[string]string
		want      int
	}{
		"unknown user":      {"user", "nobody", []map[string]string{check}, http.StatusNotFound},
		"unknown account":   {"service_account", "nobody", []map[string]string{check}, http.StatusNotFound},
		"bad actor":         {"group", "operator", []map[string]string{check}, http.StatusBadRequest},
		"no checks":         {"user", "operator", nil, http.StatusBadRequest},
		"bad entry type":    {"user", "operator", []map[string]string{{"path": check["path"], "entry_type": "unknown"}}, http.StatusBadRequest},
		"missing type":      {"user", "operator", []map[string]string{{"path": check["path"]}}, http.StatusBadRequest},
		"traversal path":    {"user", "operator", []map[string]string{{"path": "nodes/../x", "entry_type": "file"}}, http.StatusBadRequest},
		"too many checks":   {"user", "operator", manyChecks(maxEffectiveAccessChecks + 1), http.StatusBadRequest},
		"the limit is fine": {"user", "operator", manyChecks(maxEffectiveAccessChecks), http.StatusOK},
	} {
		if _, code := askEffective(t, h, "admin", test.actor, test.id, test.checks...); code != test.want {
			t.Fatalf("%s: code=%d want %d", name, code, test.want)
		}
	}
}

func manyChecks(count int) []map[string]string {
	checks := make([]map[string]string, count)
	for index := range checks {
		checks[index] = map[string]string{"path": "nodes/n1/files/mounts/m", "entry_type": "directory"}
	}
	return checks
}

func TestEffectiveAccessReportsAdminsAndFeatureOff(t *testing.T) {
	h := effectiveHarness(t, false)
	check := map[string]string{"path": "nodes/n1/files/mounts/m/docs/key.pem", "entry_type": "file"}
	out, code := askEffective(t, h, "admin", "user", "admin", check)
	if code != http.StatusOK || !out.Results[0].Capabilities["sudo"].Allowed || out.Results[0].Capabilities["read"].PolicyIDs[0] != "builtin-admin" || len(out.Notes) == 0 {
		t.Fatalf("admin: %d %+v", code, out)
	}
	// With the feature off the typed denial denies the whole path, as at runtime.
	out, code = askEffective(t, h, "admin", "user", "operator", check)
	if code != http.StatusOK || out.TypedPolicies || out.Results[0].Capabilities["read"].Allowed || len(out.Notes) != 1 {
		t.Fatalf("feature off: %d %+v", code, out)
	}
	if out.Results[0].Capabilities["read"].Typed {
		t.Fatal("legacy evaluation reported as typed")
	}
}

func TestEffectiveAccessHonoursAccessGroupNodes(t *testing.T) {
	h := effectiveHarness(t, true)
	ctx, now := context.Background(), time.Now().UTC()
	if err := h.storage.CreateServiceAccount(ctx, store.ServiceAccount{ID: "bot", Name: "bot", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.CreateAccessGroup(ctx, store.AccessGroup{ID: "g", Name: "g", Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetAccessGroupNodes(ctx, "g", []string{"n1"}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetAccessGroupPolicies(ctx, "g", []string{"typed"}); err != nil {
		t.Fatal(err)
	}
	if err := h.storage.SetServiceAccountGroups(ctx, "bot", []string{"g"}); err != nil {
		t.Fatal(err)
	}
	out, code := askEffective(t, h, "admin", "service_account", "bot",
		map[string]string{"path": "nodes/n1/files/mounts/m/a.txt", "entry_type": "file"},
		map[string]string{"path": "nodes/n2/files/mounts/m/a.txt", "entry_type": "file"})
	if code != http.StatusOK || !out.Results[0].Capabilities["read"].Allowed || out.Results[0].Reason != "" {
		t.Fatalf("member node: %d %+v", code, out)
	}
	if out.Results[1].Capabilities["read"].Allowed || out.Results[1].Reason != "node_not_in_group" {
		t.Fatalf("node outside the group: %+v", out.Results[1])
	}
}
