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
