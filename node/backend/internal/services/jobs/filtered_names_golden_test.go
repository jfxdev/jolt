package jobs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/filetypes"
)

// A typed denial of create must hold whatever way the destination name is
// written. Names that really differ (another extension, a trailing dot or
// space) are different files on this filesystem and are not a bypass; the
// non-goals in docs/proposals/file-type-restrictions.md say a writer can always
// put content under another name.
func TestPlanCopyFilteredDestinationNamesCannotEvadeATypeDenial(t *testing.T) {
	base := "nodes/node/files/mounts/mount"
	filter := copyPlanFilter(t,
		filetypes.Rule{PolicyID: "no-keys", Path: base + "/**", Capabilities: []string{"deny", "create"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}, Names: []string{".env"}}},
	)
	for _, test := range []struct {
		destination string
		refused     bool
	}{
		{"new.pem", true},
		{"NEW.PEM", true},
		{"new.Pem", true},
		{"docs/new.pem", true},
		{"docs/../new.pem", true},
		{"./new.pem", true},
		{"docs//new.pem", true},
		{"docs/./new.pem", true},
		{"a/b/../../new.pem", true},
		{"new.pem/", true},
		{" new.pem", true},
		{".pem", true},
		{".env", true},
		{"docs/.ENV", true},
		{"docs/.env/", true},
		{"new.pem.txt", false},
		{"new.pem.", false},
		{"new.pem ", false},
		{"newpem", false},
		{".env.local", false},
		{"new.txt", false},
	} {
		t.Run(test.destination, func(t *testing.T) {
			service, files, mountID := testService(t)
			mount, err := files.GetMount(context.Background(), mountID)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(mount.LocalPath, "source.txt"), []byte("source"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(mount.LocalPath, "docs"), 0o700); err != nil {
				t.Fatal(err)
			}
			_, _, err = service.PlanCopyFiltered(context.Background(), mountID, "source.txt", test.destination, "fail", filter, false)
			if refused := err != nil; refused != test.refused {
				t.Fatalf("destination %q: err=%v want refused=%v", test.destination, err, test.refused)
			}
			// Planning must not have written anything either way.
			entries, readErr := os.ReadDir(mount.LocalPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				if entry.Name() != "source.txt" && entry.Name() != "docs" && !strings.HasPrefix(entry.Name(), ".") {
					t.Fatalf("planning created %q", entry.Name())
				}
			}
		})
	}
}
