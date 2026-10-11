package rbac

import "testing"

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
