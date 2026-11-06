package httpapi

import (
	"github.com/jfxdev/jolt/control/internal/config"
	"net/http"
	"testing"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

// A share names what it shares, so typed rules are judged for that type: a
// folder called like a key is a folder, and a key is a key.
func TestShareCreationJudgesTypedRulesForTheKindOfTheEntry(t *testing.T) {
	h := newTrashHarness(t, []rbac.Rule{
		{Path: approvalMount + "/docs/**", Capabilities: []string{"read", "list"}},
		{Path: approvalMount + "/docs/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{Path: "control-tower/shares", Capabilities: []string{"create", "list"}},
	}, func(cfgPtr *config.Config) {
		cfgPtr.TypedPolicies, cfgPtr.SignedLocalReads, cfgPtr.SignedUploads, cfgPtr.SignedLocalJobs = true, true, true, true
	})
	share := func(path, kind string) int {
		return h.do("operator", http.MethodPost, "/api/v1/control-tower/shares", map[string]any{"node_id": "n1", "mount_id": "m", "path": path, "kind": kind}).Code
	}
	for _, test := range []struct {
		name, path, kind string
		want             int
	}{
		{"a plain file", "docs/report.txt", "file", http.StatusCreated},
		{"a key as a file", "docs/key.pem", "file", http.StatusForbidden},
		{"a folder called like a key", "docs/archive.pem", "directory", http.StatusCreated},
		{"a folder holding keys", "docs", "directory", http.StatusCreated},
		{"outside every rule", "other/report.txt", "file", http.StatusForbidden},
	} {
		if got := share(test.path, test.kind); got != test.want {
			t.Fatalf("%s: %d want %d", test.name, got, test.want)
		}
	}
}
