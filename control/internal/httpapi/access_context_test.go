package httpapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

func TestBuildMountAccessContextPreservesRulesAndScope(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	selector := &filetypes.Selector{Extensions: []string{"pem"}}
	policies := []rbac.Policy{
		{ID: "legacy", Rules: []rbac.Rule{{Path: "workers/n/files/mounts/m", Capabilities: []string{"read", "list"}}}},
		{ID: "typed", Rules: []rbac.Rule{{Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: selector, Visibility: "visible"}}},
		{ID: "private", Rules: []rbac.Rule{{Path: base + "/secret", Capabilities: []string{"deny"}}}},
		{ID: "other", Rules: []rbac.Rule{{Path: "nodes/n/files/mounts/other/**", Capabilities: []string{"deny"}}}},
	}
	context, err := buildMountAccessContext(policies, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.Rules) != 4 {
		t.Fatalf("unexpected rules: %+v", context.Rules)
	}
	// The signed context must be a snapshot, not a pointer into mutable policy data.
	selector.Extensions[0] = "txt"
	policies[0].Rules[0].Capabilities[0] = "delete"
	filter, err := context.Compile()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, cap, kind string
		allowed, denied bool
		visibility      string
	}{
		{base + "/ok.txt", "read", "file", true, false, "hidden"},
		{base + "/key.pem", "read", "file", false, true, "visible"},
		{base + "/key.pem", "list", "file", true, false, "hidden"},
		{base + "/secret", "list", "directory", false, true, "hidden"},
	} {
		got := filter.Evaluate(tc.path, tc.cap, tc.kind)
		if got.Allowed != tc.allowed || got.Denied != tc.denied || got.Visibility != tc.visibility {
			t.Fatalf("%s %s: %+v", tc.path, tc.cap, got)
		}
	}
}

func TestBuildMountAccessContextFailsClosed(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	if _, err := buildMountAccessContext(nil, "nodes/*/files/mounts/m"); err == nil {
		t.Fatal("wildcard scope accepted")
	}
	if _, err := buildMountAccessContext([]rbac.Policy{{ID: "p", Rules: []rbac.Rule{{Path: "nodes/n/**/bad", Capabilities: []string{"read"}}}}}, base); err == nil {
		t.Fatal("invalid rule was silently ignored")
	}
	policy := rbac.Policy{ID: "p"}
	for i := 0; i <= filetypes.MaxContextRules; i++ {
		policy.Rules = append(policy.Rules, rbac.Rule{Path: base + "/" + fmt.Sprint(i), Capabilities: []string{"read"}})
	}
	if _, err := buildMountAccessContext([]rbac.Policy{policy}, base); err == nil {
		t.Fatal("excessive rules accepted")
	}
	policy.Rules = policy.Rules[:filetypes.MaxContextRules]
	for i := range policy.Rules {
		policy.Rules[i].Path = base + "/" + fmt.Sprint(i) + strings.Repeat("x", 180)
	}
	if _, err := buildMountAccessContext([]rbac.Policy{policy}, base); err == nil {
		t.Fatal("oversized context accepted")
	}
}
