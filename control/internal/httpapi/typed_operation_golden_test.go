package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
	"github.com/jfxdev/jolt/control/internal/store"
)

type goldenRule struct {
	Path         string              `json:"path"`
	Capabilities []string            `json:"capabilities"`
	FileTypes    *filetypes.Selector `json:"file_types"`
	Visibility   string              `json:"visibility"`
}

type goldenOperation struct {
	Name     string         `json:"name"`
	Set      string         `json:"set"`
	Method   string         `json:"method"`
	Path     string         `json:"path"`
	Body     map[string]any `json:"body"`
	Outcome  []string       `json:"outcome"`
	NodePath *string        `json:"node_path"`
	// Profile names the node the case runs against; empty means current.
	Profile string `json:"profile"`
	// MustNotContain is a marker the node's answer carries and the caller must
	// never receive; StatusNot lists statuses the caller must not get.
	MustNotContain string `json:"must_not_contain"`
	StatusNot      []int  `json:"status_not"`
}

type goldenNodeProfile struct {
	Capabilities []string `json:"capabilities"`
	Confirms     bool     `json:"confirms"`
	ProbeStatus  int      `json:"probe_status"`
}

type nodeCall struct {
	method, path, query string
	signed              bool
}

// classifyNodeCalls names what reached the node: nothing (refused), only
// non-mutating preparation of a protected copy, whose enforcement is the node's
// (prepared), a request carrying a signed policy context (signed), or a request
// with none (plain).
func classifyNodeCalls(calls []nodeCall) string {
	if len(calls) == 0 {
		return "refused"
	}
	outcome := "prepared"
	for _, call := range calls {
		switch {
		case call.path == "/api/v1/jobs/signed-local-copy/prepare":
		case call.signed:
			if outcome == "prepared" {
				outcome = "signed"
			}
		default:
			return "plain"
		}
	}
	return outcome
}

// TestTypedOperationGoldenCases runs file operations with tricky names through
// the Control Tower and checks only what must never vary: when a typed rule
// covers a path, the operation is either refused here, deferred to the node
// through a protected copy, or reaches the node with a signed policy context. A
// request that reaches the node unsigned is allowed only for operations the
// Control Tower itself decided.
func TestTypedOperationGoldenCases(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "typed-operation-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Mount        string                       `json:"mount"`
		PolicySets   map[string][]goldenRule      `json:"policy_sets"`
		NodeProfiles map[string]goldenNodeProfile `json:"node_profiles"`
		Cases        []goldenOperation            `json:"cases"`
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	type group struct{ set, profile string }
	groups := map[group]bool{}
	for _, tc := range golden.Cases {
		if tc.Profile == "" {
			tc.Profile = "current"
		}
		groups[group{tc.Set, tc.Profile}] = true
	}
	for g := range groups {
		set, rules, profile := g.set, golden.PolicySets[g.set], golden.NodeProfiles[g.profile]
		var calls []nodeCall
		h := newTypedHarness(t, true, func(r *http.Request) (int, http.Header, string) {
			header := make(http.Header)
			header.Set("Content-Type", "application/json")
			if r.URL.Path == "/api/v1/node" {
				if profile.ProbeStatus != 0 {
					return profile.ProbeStatus, header, `{}`
				}
				capabilities, _ := json.Marshal(profile.Capabilities)
				return 200, header, `{"node_id":"n1","capabilities":` + string(capabilities) + `}`
			}
			signed := r.Header.Get(signedAuthorizationHeader) != ""
			calls = append(calls, nodeCall{method: r.Method, path: r.URL.Path, query: r.URL.Query().Get("path"), signed: signed})
			if signed && profile.Confirms {
				header.Set("X-Jolt-Access-Applied", "v1")
			}
			return 200, header, `{"items":[],"marker":"LEAKED"}`
		})
		policy := store.Policy{ID: set, Name: set, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		for _, rule := range rules {
			policy.Rules = append(policy.Rules, rbac.Rule{Path: rule.Path, Capabilities: rule.Capabilities, FileTypes: rule.FileTypes, Visibility: rule.Visibility})
		}
		if err := h.storage.CreatePolicy(context.Background(), policy); err != nil {
			t.Fatal(err)
		}
		if err := h.storage.SetSubjectPolicies(context.Background(), "user", "operator", []string{set}); err != nil {
			t.Fatal(err)
		}
		for _, tc := range golden.Cases {
			if tc.Profile == "" {
				tc.Profile = "current"
			}
			if tc.Set != set || tc.Profile != g.profile {
				continue
			}
			t.Run(set+"/"+tc.Profile+"/"+tc.Name, func(t *testing.T) {
				calls = nil
				var body any
				if tc.Body != nil {
					body = tc.Body
				}
				response := h.do("operator", tc.Method, "/api/v1/nodes/n1/mounts/m/"+tc.Path, body)
				outcome := classifyNodeCalls(calls)
				if !slices.Contains(tc.Outcome, outcome) {
					t.Fatalf("outcome %s (status %d, calls %+v) not in %v: %s", outcome, response.Code, calls, tc.Outcome, response.Body)
				}
				if outcome == "refused" && response.Code < 400 {
					t.Fatalf("refused but status %d", response.Code)
				}
				if tc.MustNotContain != "" && strings.Contains(response.Body.String(), tc.MustNotContain) {
					t.Fatalf("the caller received the node's answer: %s", response.Body)
				}
				if slices.Contains(tc.StatusNot, response.Code) {
					t.Fatalf("status %d must not be returned: %s", response.Code, response.Body)
				}
				if tc.NodePath != nil {
					found := false
					for _, call := range calls {
						found = found || call.query == *tc.NodePath
					}
					if !found {
						t.Fatalf("the node did not act on %q: %+v", *tc.NodePath, calls)
					}
				}
			})
		}
	}
}
