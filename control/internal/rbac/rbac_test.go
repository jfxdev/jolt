package rbac

import (
	"testing"

	"github.com/jfxdev/jolt/control/internal/filetypes"
)

func TestTypedRulesFailClosedInPathOnlyEvaluator(t *testing.T) {
	path := "nodes/n/files/mounts/m"
	selector := &filetypes.Selector{Extensions: []string{"pem"}}
	allow := Rule{Path: path, Capabilities: []string{"read"}, FileTypes: selector, Visibility: "visible"}
	expanded := ExpandCompatibilityRules([]Policy{{ID: "typed", Rules: []Rule{allow}}})
	if len(expanded[0].Rules) != 2 || expanded[0].Rules[1].FileTypes != selector || expanded[0].Rules[1].Visibility != "visible" {
		t.Fatalf("compatibility expansion lost typed fields: %+v", expanded)
	}
	if decision := Evaluate(expanded, path+"/example.pem", "read"); decision.Allowed {
		t.Fatalf("path-only evaluator granted typed rule: %+v", decision)
	}
	deny := Rule{Path: path, Capabilities: []string{"deny", "read"}, FileTypes: selector}
	policies := ExpandCompatibilityRules([]Policy{{ID: "allow", Rules: []Rule{{Path: path, Capabilities: []string{"read"}}}}, {ID: "deny", Rules: []Rule{deny}}})
	if decision := Evaluate(policies, path+"/example.txt", "read"); !decision.Denied {
		t.Fatalf("path-only evaluator ignored typed denial: %+v", decision)
	}
}

func TestUntypedDeniesWithinExcludesTypedDenialsOnly(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	typed := Policy{ID: "typed", Rules: []Rule{{Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}}}
	if !DeniesWithin([]Policy{typed}, base) {
		t.Fatal("legacy subtree guard ignored typed denial")
	}
	if UntypedDeniesWithin([]Policy{typed}, base) {
		t.Fatal("typed denial blocked an otherwise filterable tree")
	}
	pathDeny := Policy{ID: "path", Rules: []Rule{{Path: base + "/private/**", Capabilities: []string{"deny"}}}}
	if !UntypedDeniesWithin([]Policy{typed, pathDeny}, base) {
		t.Fatal("descendant path denial did not block tree")
	}
	if UntypedDeniesWithin([]Policy{pathDeny}, base+"/public") {
		t.Fatal("unrelated sibling was blocked")
	}
}

func TestDenyAlwaysWins(t *testing.T) {
	policies := []Policy{
		{ID: "allow", Rules: []Rule{{Path: "nodes/*/transfers", Capabilities: []string{"execute"}}}},
		{ID: "deny", Rules: []Rule{{Path: "nodes/node-a/transfers", Capabilities: []string{"deny"}}}},
	}
	decision := Evaluate(policies, "nodes/node-a/transfers", "execute")
	if decision.Allowed || !decision.Denied || len(decision.PolicyIDs) != 1 || decision.PolicyIDs[0] != "deny" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestSpecificPathAllowAndWriteAlias(t *testing.T) {
	policies := []Policy{
		{ID: "files", Rules: []Rule{{Path: "nodes/node-a/files/mounts/media", Capabilities: []string{"read", "write"}}}},
	}
	if decision := Evaluate(policies, "nodes/node-a/files/mounts/media", "create"); !decision.Allowed {
		t.Fatalf("write did not grant create: %+v", decision)
	}
	if decision := Evaluate(policies, "nodes/node-a/files/mounts/private", "read"); decision.Allowed {
		t.Fatalf("policy leaked to another mount: %+v", decision)
	}
	if decision := Evaluate(policies, "nodes/node-a/transfers", "execute"); decision.Allowed {
		t.Fatalf("files policy leaked into transfers: %+v", decision)
	}
}

func TestValidPathRejectsFilesystemSyntax(t *testing.T) {
	for _, value := range []string{"", "/nodes//node", "nodes/node/files?path=secret", "nodes/node/../admin"} {
		if ValidPath(value) {
			t.Fatalf("path %q should be invalid", value)
		}
	}
	if !ValidPath("nodes/*/files/mounts/media") {
		t.Fatal("expected node path to be valid")
	}
	if got := NormalizePath("workers/node-a/files"); got != "nodes/node-a/files" {
		t.Fatalf("legacy path normalized to %q", got)
	}
}

func TestRecursivePathCoversSubtreeAndItself(t *testing.T) {
	policies := []Policy{{ID: "p-photos", Rules: []Rule{
		{Path: "nodes/*/files/mounts/media/photos/**", Capabilities: []string{"read", "list"}},
	}}}
	for _, path := range []string{
		"nodes/node-a/files/mounts/media/photos",
		"nodes/node-a/files/mounts/media/photos/2024",
		"nodes/node-a/files/mounts/media/photos/2024/ferias/praia.jpg",
	} {
		if decision := Evaluate(policies, path, "read"); !decision.Allowed {
			t.Fatalf("recursive rule did not cover %q: %+v", path, decision)
		}
	}
	// A sibling subtree inside the same mount stays out of scope.
	if decision := Evaluate(policies, "nodes/node-a/files/mounts/media/documentos", "read"); decision.Allowed {
		t.Fatal("recursive rule leaked into a sibling subtree")
	}
	// The mount root above the rule is not granted either.
	if decision := Evaluate(policies, "nodes/node-a/files/mounts/media", "read"); decision.Allowed {
		t.Fatal("recursive rule leaked upward to the mount root")
	}
}

func TestRecursiveDenyOverridesSubtreeAllow(t *testing.T) {
	policies := []Policy{
		{ID: "p-allow", Rules: []Rule{
			{Path: "nodes/node-a/files/mounts/media/**", Capabilities: []string{"read"}},
		}},
		{ID: "p-deny", Rules: []Rule{
			{Path: "nodes/node-a/files/mounts/media/privado/**", Capabilities: []string{"deny"}},
		}},
	}
	if decision := Evaluate(policies, "nodes/node-a/files/mounts/media/publico/a.txt", "read"); !decision.Allowed {
		t.Fatalf("allow outside the denied subtree was refused: %+v", decision)
	}
	for _, path := range []string{
		"nodes/node-a/files/mounts/media/privado",
		"nodes/node-a/files/mounts/media/privado/fiscal/nota.pdf",
	} {
		decision := Evaluate(policies, path, "read")
		if !decision.Denied || decision.Allowed {
			t.Fatalf("deny did not take precedence on %q: %+v", path, decision)
		}
	}
}

func TestValidPathAcceptsRealFilenamesAndRejectsMisplacedRecursion(t *testing.T) {
	for _, value := range []string{
		"nodes/*/files/mounts/media/**",
		"nodes/node-a/files/mounts/media/Fotos de Família",
		"nodes/node-a/files/mounts/media/Relatório (2024)/**",
	} {
		if !ValidPath(value) {
			t.Fatalf("path %q should be valid", value)
		}
	}
	for _, value := range []string{
		"nodes/**/files",
		"nodes/node-a/files/mounts/media/**/private",
		"nodes/node-a/files/mounts/me*dia",
	} {
		if ValidPath(value) {
			t.Fatalf("path %q should be invalid", value)
		}
	}
}

func TestExpandCompatibilityRulesPreservesLegacyMountAccess(t *testing.T) {
	legacy := []Policy{{ID: "p-legacy", Rules: []Rule{
		{Path: "nodes/*/files/mounts/media", Capabilities: []string{"read", "list", "create"}},
	}}}
	// Before subpath evaluation this rule authorized every path in the mount.
	if decision := Evaluate(legacy, "nodes/node-a/files/mounts/media/photos/a.jpg", "read"); decision.Allowed {
		t.Fatal("unexpanded legacy rule should not match a subpath")
	}
	expanded := ExpandCompatibilityRules(legacy)
	for _, path := range []string{
		"nodes/node-a/files/mounts/media",
		"nodes/node-a/files/mounts/media/photos/a.jpg",
	} {
		if decision := Evaluate(expanded, path, "read"); !decision.Allowed {
			t.Fatalf("expanded legacy rule did not cover %q: %+v", path, decision)
		}
	}
	// Expansion must not reach a different mount or a non-file resource.
	if decision := Evaluate(expanded, "nodes/node-a/files/mounts/private/a.jpg", "read"); decision.Allowed {
		t.Fatal("expansion leaked into another mount")
	}
	if decision := Evaluate(expanded, "nodes/node-a/transfers", "execute"); decision.Allowed {
		t.Fatal("expansion leaked into transfers")
	}
}

func TestExpandCompatibilityRulesExpandsDenyToo(t *testing.T) {
	policies := ExpandCompatibilityRules([]Policy{
		{ID: "p-allow", Rules: []Rule{
			{Path: "nodes/node-a/files/mounts/media/**", Capabilities: []string{"read"}},
		}},
		{ID: "p-deny", Rules: []Rule{
			{Path: "nodes/node-a/files/mounts/media", Capabilities: []string{"deny"}},
		}},
	})
	decision := Evaluate(policies, "nodes/node-a/files/mounts/media/photos/a.jpg", "read")
	if !decision.Denied {
		t.Fatalf("a legacy mount-wide deny must still deny subpaths: %+v", decision)
	}
}

func TestExactRuleOutranksRecursiveRuleAtSameDepth(t *testing.T) {
	policies := []Policy{
		{ID: "p-broad", Rules: []Rule{
			{Path: "nodes/node-a/files/mounts/media/**", Capabilities: []string{"read"}},
		}},
		{ID: "p-exact", Rules: []Rule{
			{Path: "nodes/node-a/files/mounts/media/photos", Capabilities: []string{"read"}},
		}},
	}
	decision := Evaluate(policies, "nodes/node-a/files/mounts/media/photos", "read")
	if !decision.Allowed {
		t.Fatalf("expected access: %+v", decision)
	}
	if len(decision.PolicyIDs) != 1 || decision.PolicyIDs[0] != "p-exact" {
		t.Fatalf("expected the exact rule to win attribution, got %v", decision.PolicyIDs)
	}
}

func TestValidResourcePathAcceptsRealNamesButNotPatterns(t *testing.T) {
	// A concrete path carries user data: a folder really can be named
	// "Vendas 50% off", and refusing it would deny access to it. These names
	// are accepted as resources but refused as authored policy rules, where a
	// URL metacharacter would make the rule ambiguous.
	for _, value := range []string{
		"nodes/node-a/files/mounts/media/Vendas 50% off/nota #12.pdf",
		"nodes/node-a/files/mounts/media/a&b",
		"nodes/node-a/files/mounts/media/q=1",
	} {
		if !ValidResourcePath(value) {
			t.Fatalf("resource path %q should be valid", value)
		}
		if ValidPath(value) {
			t.Fatalf("policy path %q should be invalid", value)
		}
	}
	// Spaces, accents and ordinary punctuation are valid in both roles.
	for _, value := range []string{
		"nodes/node-a/files/mounts/media/Relatório (2024).pdf",
		"nodes/node-a/files/mounts/media/Fotos de Família",
	} {
		if !ValidResourcePath(value) || !ValidPath(value) {
			t.Fatalf("path %q should be valid in both roles", value)
		}
	}
	for _, value := range []string{
		"", "nodes//node", "nodes/node/../admin", "nodes/*/files",
		"nodes/node/files/**", "nodes/node/.",
	} {
		if ValidResourcePath(value) {
			t.Fatalf("resource path %q should be invalid", value)
		}
	}
}

func TestDeniesWithinDetectsDenyAtOrBelowScope(t *testing.T) {
	policies := []Policy{{ID: "p", Rules: []Rule{
		{Path: "nodes/*/files/mounts/media/**", Capabilities: []string{"read", "list"}},
		{Path: "nodes/*/files/mounts/media/privado/**", Capabilities: []string{"deny"}},
	}}}
	// Reading a subtree that contains the denied folder must be refused: the
	// node would otherwise stream files the subject cannot read.
	for _, scope := range []string{
		"nodes/node-a/files/mounts/media",
		"nodes/node-a/files/mounts/media/privado",
		"nodes/node-a/files/mounts/media/privado/contabilidade",
	} {
		if !DeniesWithin(policies, scope) {
			t.Fatalf("deny not detected within %q", scope)
		}
	}
	// A sibling subtree holds no deny rule and stays readable as a whole.
	for _, scope := range []string{
		"nodes/node-a/files/mounts/media/publico",
		"nodes/node-a/files/mounts/media/publico/fotos",
		"nodes/node-a/files/mounts/outro",
	} {
		if DeniesWithin(policies, scope) {
			t.Fatalf("false positive for %q", scope)
		}
	}
}

func TestDeniesWithinHandlesExactAndAncestorRules(t *testing.T) {
	exact := []Policy{{ID: "p", Rules: []Rule{
		{Path: "nodes/node-a/files/mounts/media/privado", Capabilities: []string{"deny"}},
	}}}
	// An exact deny on a folder blocks archiving its parent, because the
	// archive would include that folder.
	if !DeniesWithin(exact, "nodes/node-a/files/mounts/media") {
		t.Fatal("an exact deny below the scope was missed")
	}
	if !DeniesWithin(exact, "nodes/node-a/files/mounts/media/privado") {
		t.Fatal("an exact deny at the scope was missed")
	}
	// A non-recursive deny on an ancestor does not itself deny the descendant.
	if DeniesWithin(exact, "nodes/node-a/files/mounts/media/privado/sub") {
		t.Fatal("a non-recursive ancestor deny leaked downward")
	}
	recursive := []Policy{{ID: "p", Rules: []Rule{
		{Path: "nodes/node-a/files/mounts/media/**", Capabilities: []string{"deny"}},
	}}}
	// A recursive deny above the scope does reach into it.
	if !DeniesWithin(recursive, "nodes/node-a/files/mounts/media/privado/sub") {
		t.Fatal("a recursive ancestor deny was missed")
	}
}

func TestDeniesWithinIgnoresAllowRulesAndOtherFamilies(t *testing.T) {
	policies := []Policy{{ID: "p", Rules: []Rule{
		{Path: "nodes/*/files/mounts/media/**", Capabilities: []string{"read"}},
		{Path: "nodes/*/transfers", Capabilities: []string{"deny"}},
	}}}
	if DeniesWithin(policies, "nodes/node-a/files/mounts/media") {
		t.Fatal("an allow rule or an unrelated family triggered a deny")
	}
}

func TestNeedsApprovalFollowsTheMostSpecificGrant(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	policies := []Policy{
		{ID: "wide", Rules: []Rule{{Path: base + "/**", Capabilities: []string{"read", "delete"}, NeedsApproval: []string{"delete"}}}},
		{ID: "plain", Rules: []Rule{{Path: base + "/scratch/**", Capabilities: []string{"delete"}}}},
		{ID: "write", Rules: []Rule{{Path: base + "/inbox/**", Capabilities: []string{"write"}, NeedsApproval: []string{"update"}}}},
	}
	for _, test := range []struct {
		path, capability  string
		allowed, approval bool
	}{
		{base + "/docs/a.txt", "delete", true, true},
		{base + "/docs/a.txt", "read", true, false},
		{base + "/scratch/a.txt", "delete", true, false}, // a more specific, unmarked grant wins
		{base + "/inbox/a.txt", "update", true, true},    // write grants update, and the mark names update
		{base + "/inbox/a.txt", "create", true, false},   // the mark is per capability
		{base + "/docs/a.txt", "update", false, false},
	} {
		got := Evaluate(policies, test.path, test.capability)
		if got.Allowed != test.allowed || got.NeedsApproval != test.approval {
			t.Fatalf("%s %s: %+v", test.path, test.capability, got)
		}
	}
	// Two grants at the same specificity: one mark is enough.
	both := []Policy{
		{ID: "a", Rules: []Rule{{Path: base + "/x/**", Capabilities: []string{"delete"}}}},
		{ID: "b", Rules: []Rule{{Path: base + "/x/**", Capabilities: []string{"delete"}, NeedsApproval: []string{"delete"}}}},
	}
	if got := Evaluate(both, base+"/x/f", "delete"); !got.Allowed || !got.NeedsApproval {
		t.Fatalf("a mark at the same specificity was dropped: %+v", got)
	}
	// A denial still wins and carries no approval.
	denied := append([]Policy{{ID: "d", Rules: []Rule{{Path: base + "/**", Capabilities: []string{"deny"}}}}}, policies...)
	if got := Evaluate(denied, base+"/docs/a.txt", "delete"); got.Allowed || got.NeedsApproval {
		t.Fatalf("denial: %+v", got)
	}
}

func TestTypedEvaluatorsKeepTheApprovalMarkOfPathRules(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	policies := []Policy{
		{ID: "wide", Rules: []Rule{{Path: base + "/**", Capabilities: []string{"read", "delete"}, NeedsApproval: []string{"delete"}}}},
		{ID: "no-keys", Rules: []Rule{{Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}}},
	}
	// The typed denial makes the path evaluator deny everything here, so only
	// the typed evaluators can say a plain file may be deleted. They must not
	// lose the mark while doing it.
	if got := EvaluateEntry(policies, base+"/a.txt", "delete", "file"); !got.Allowed || !got.NeedsApproval {
		t.Fatalf("entry: %+v", got)
	}
	for _, mode := range []EntryMode{EveryEntry, NodeFiltered} {
		if got := EvaluateTyped(policies, base+"/a.txt", "delete", mode); !got.Allowed || !got.NeedsApproval {
			t.Fatalf("mode %d: %+v", mode, got)
		}
	}
	if got := EvaluateEntry(policies, base+"/a.txt", "read", "file"); !got.Allowed || got.NeedsApproval {
		t.Fatalf("an unmarked capability asked for approval: %+v", got)
	}
}

func TestValidNeedsApproval(t *testing.T) {
	for name, test := range map[string]struct {
		rule Rule
		ok   bool
	}{
		"none":               {Rule{Path: "nodes/n", Capabilities: []string{"read"}}, true},
		"delete":             {Rule{Path: "nodes/n", Capabilities: []string{"delete"}, NeedsApproval: []string{"delete"}}, true},
		"update via write":   {Rule{Path: "nodes/n", Capabilities: []string{"write"}, NeedsApproval: []string{"update"}}, true},
		"both":               {Rule{Path: "nodes/n", Capabilities: []string{"delete", "update"}, NeedsApproval: []string{"delete", "update"}}, true},
		"not granted":        {Rule{Path: "nodes/n", Capabilities: []string{"read"}, NeedsApproval: []string{"delete"}}, false},
		"not destructive":    {Rule{Path: "nodes/n", Capabilities: []string{"read"}, NeedsApproval: []string{"read"}}, false},
		"on a denial":        {Rule{Path: "nodes/n", Capabilities: []string{"deny", "delete"}, NeedsApproval: []string{"delete"}}, false},
		"on a typed rule":    {Rule{Path: "nodes/n", Capabilities: []string{"delete"}, NeedsApproval: []string{"delete"}, FileTypes: &filetypes.Selector{Extensions: []string{"x"}}}, false},
		"repeated":           {Rule{Path: "nodes/n", Capabilities: []string{"delete"}, NeedsApproval: []string{"delete", "delete"}}, false},
		"upper case":         {Rule{Path: "nodes/n", Capabilities: []string{"delete"}, NeedsApproval: []string{"DELETE"}}, false},
		"unknown capability": {Rule{Path: "nodes/n", Capabilities: []string{"delete"}, NeedsApproval: []string{"sudo"}}, false},
	} {
		if got := ValidNeedsApproval(test.rule); got != test.ok {
			t.Fatalf("%s: %v", name, got)
		}
	}
}

func TestMatchingRulesShowWhatADecisionWasMadeFrom(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	policies := []Policy{
		{ID: "wide", Rules: []Rule{{Path: base + "/**", Capabilities: []string{"read", "list", "delete"}, NeedsApproval: []string{"delete"}}}},
		{ID: "no-keys", Rules: []Rule{{Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}, Visibility: "visible"}}},
		{ID: "vault", Rules: []Rule{{Path: base + "/vault/**", Capabilities: []string{"deny"}}}},
		{ID: "elsewhere", Rules: []Rule{{Path: "nodes/other/**", Capabilities: []string{"read"}}}},
		{ID: "writes", Rules: []Rule{{Path: base + "/inbox/**", Capabilities: []string{"write"}}}},
	}
	effects := func(path, capability string) map[string]string {
		result := map[string]string{}
		for _, match := range MatchingRules(policies, path, capability) {
			result[match.PolicyID] = match.Effect
		}
		return result
	}
	want := func(got, expected map[string]string) {
		t.Helper()
		if len(got) != len(expected) {
			t.Fatalf("got %v want %v", got, expected)
		}
		for key, value := range expected {
			if got[key] != value {
				t.Fatalf("got %v want %v", got, expected)
			}
		}
	}
	want(effects(base+"/docs/a.txt", "read"), map[string]string{"wide": "allow", "no-keys": "typed_deny"})
	// A typed denial that names only read says nothing about delete.
	want(effects(base+"/docs/a.txt", "delete"), map[string]string{"wide": "allow"})
	// A path denial bears on every capability.
	want(effects(base+"/vault/x", "list"), map[string]string{"wide": "allow", "vault": "deny"})
	// Write grants update, so the rule that gives it is a cause of an update.
	want(effects(base+"/inbox/f", "update"), map[string]string{"writes": "allow"})
	// A rule for another node never appears.
	if _, found := effects(base+"/docs/a.txt", "read")["elsewhere"]; found {
		t.Fatal("a rule that does not cover the path was listed")
	}
	marked := MatchingRules(policies, base+"/docs/a.txt", "delete")
	if len(marked) != 1 || len(marked[0].NeedsApproval) != 1 {
		t.Fatalf("the approval mark was lost: %+v", marked)
	}
}
