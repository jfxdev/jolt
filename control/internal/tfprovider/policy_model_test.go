package tfprovider

import (
	"context"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

func TestPolicyModelRoundTrip(t *testing.T) {
	ctx := context.Background()
	want := PolicyInput{Name: "typed", Description: "d", Rules: []rbac.Rule{
		{Path: "nodes/n1/files/mounts/m/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}, Visibility: "visible"},
		{Path: "nodes/n1/files/mounts/m/inbox/**", Capabilities: []string{"read", "delete"}, NeedsApproval: []string{"delete"}},
	}}
	var model policyModel
	if diags := model.setPolicy(ctx, Policy{ID: "pol_1", Name: want.Name, Description: want.Description, Rules: want.Rules}); diags.HasError() {
		t.Fatal(diags)
	}
	if diags := model.validate(ctx); diags.HasError() {
		t.Fatalf("valid policy refused: %v", diags)
	}
	got, diags := model.input(ctx)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if got.Name != want.Name || len(got.Rules) != 2 || got.Rules[0].FileTypes == nil || got.Rules[0].FileTypes.Extensions[0] != "pem" ||
		got.Rules[0].Visibility != "visible" || got.Rules[0].FileTypes.Classes != nil || got.Rules[1].FileTypes != nil || got.Rules[1].NeedsApproval[0] != "delete" {
		t.Fatalf("round trip changed the policy: %+v", got)
	}
}

func TestPolicyModelRefusesWhatTheServerWouldRewriteOrRefuse(t *testing.T) {
	ctx := context.Background()
	for name, test := range map[string]struct {
		description string
		rule        rbac.Rule
		want        string
	}{
		"leading slash":      {rule: rbac.Rule{Path: "/nodes/n1/**", Capabilities: []string{"read"}}, want: `"nodes/n1/**"`},
		"workers alias":      {rule: rbac.Rule{Path: "workers/n1", Capabilities: []string{"read"}}, want: `"nodes/n1"`},
		"inner recursion":    {rule: rbac.Rule{Path: "nodes/**/files", Capabilities: []string{"read"}}, want: "Invalid path"},
		"deny with grants":   {rule: rbac.Rule{Path: "nodes/n1", Capabilities: []string{"deny", "read"}}, want: "deny stands alone"},
		"unknown class":      {rule: rbac.Rule{Path: "nodes/n1", Capabilities: []string{"read"}, FileTypes: &filetypes.Selector{Classes: []string{"spreadsheet"}}}, want: "Invalid file types"},
		"bare visibility":    {rule: rbac.Rule{Path: "nodes/n1", Capabilities: []string{"read"}, Visibility: "visible"}, want: "visibility needs file_types"},
		"approval not held":  {rule: rbac.Rule{Path: "nodes/n1", Capabilities: []string{"read"}, NeedsApproval: []string{"delete"}}, want: "Invalid needs_approval"},
		"approval with deny": {rule: rbac.Rule{Path: "nodes/n1", Capabilities: []string{"deny"}, NeedsApproval: []string{"delete"}}, want: "Invalid needs_approval"},
		"padded description": {description: " d ", rule: rbac.Rule{Path: "nodes/n1", Capabilities: []string{"read"}}, want: "surrounding spaces"},
	} {
		t.Run(name, func(t *testing.T) {
			var model policyModel
			if diags := model.setPolicy(ctx, Policy{ID: "pol_1", Name: "p", Description: test.description, Rules: []rbac.Rule{test.rule}}); diags.HasError() {
				t.Fatal(diags)
			}
			diags := model.validate(ctx)
			if !diags.HasError() {
				t.Fatal("accepted")
			}
			text := ""
			for _, d := range diags.Errors() {
				text += d.Summary() + " " + d.Detail() + "\n"
			}
			if !strings.Contains(text, test.want) {
				t.Fatalf("diagnostics %q do not mention %q", text, test.want)
			}
		})
	}
}
