package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/filetypes"
)

func TestManifestFilteredOmitsRestrictedEntriesBeforeCounting(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source", "public.txt"), "public")
	writeFile(t, filepath.Join(root, "source", "hidden.pem"), "secret")
	writeFile(t, filepath.Join(root, "source", "blocked.lock"), "blocked")
	writeFile(t, filepath.Join(root, "source", "private", "nested.txt"), "hidden tree")
	writeFile(t, filepath.Join(root, "source", "folder.pem", "inside.txt"), "visible")
	writeFile(t, filepath.Join(root, "source", ".jolt-job.partial"), "internal")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read"}},
		{PolicyID: "pem", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "lock", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"lock"}}, Visibility: "visible"},
		{PolicyID: "private", Path: base + "/source/private/**", Capabilities: []string{"deny"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	entries, omitted, err := service.ManifestFiltered(context.Background(), mountID, "source", filter)
	if err != nil || omitted != 4 {
		t.Fatalf("entries=%+v omitted=%d err=%v", entries, omitted, err)
	}
	got := map[string]string{}
	var total int64
	for _, entry := range entries {
		got[entry.Path] = entry.Type
		if entry.Type == "file" {
			total += entry.Size
		}
	}
	if len(got) != 3 || got["public.txt"] != "file" || got["folder.pem"] != "directory" || got["folder.pem/inside.txt"] != "file" || total != int64(len("public")+len("visible")) {
		t.Fatalf("filtered manifest=%v total=%d", got, total)
	}
	if _, _, err := service.ManifestFiltered(context.Background(), mountID, "source/hidden.pem", filter); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("direct hidden source: %v", err)
	}
	if _, _, err := service.ManifestFiltered(context.Background(), mountID, "source/blocked.lock", filter); !errors.Is(err, ErrFilteredBlocked) {
		t.Fatalf("direct blocked source: %v", err)
	}
	checksum, err := service.ChecksumFiltered(context.Background(), mountID, "source/public.txt", filter)
	want := sha256.Sum256([]byte("public"))
	if err != nil || checksum != hex.EncodeToString(want[:]) {
		t.Fatalf("checksum=%q err=%v", checksum, err)
	}
	if _, err := service.ChecksumFiltered(context.Background(), mountID, "source/hidden.pem", filter); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("hidden checksum: %v", err)
	}
	if _, _, err := service.ManifestFiltered(context.Background(), mountID, "source", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil filter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if entries, omitted, err := service.ManifestFiltered(ctx, mountID, "source", filter); !errors.Is(err, context.Canceled) || entries != nil || omitted != 0 {
		t.Fatalf("canceled manifest=%+v omitted=%d err=%v", entries, omitted, err)
	}
}

func TestManifestFilteredRejectsSymlinksWithoutPartialResults(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source", "allowed.txt"), "allowed")
	if err := os.Symlink("allowed.txt", filepath.Join(root, "source", "link.txt")); err != nil {
		t.Fatal(err)
	}
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read"}}}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	entries, omitted, err := service.ManifestFiltered(context.Background(), mountID, "source", filter)
	if !errors.Is(err, ErrInvalid) || entries != nil || omitted != 0 {
		t.Fatalf("symlink manifest=%+v omitted=%d err=%v", entries, omitted, err)
	}
}

func TestManifestFilteredDoesNotExposeReadableButUnlistedFiles(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source", "unlisted.txt"), "private")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "list", Path: base + "/source", Capabilities: []string{"list"}},
		{PolicyID: "read", Path: base + "/source/unlisted.txt", Capabilities: []string{"read"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := service.OpenFiltered(context.Background(), mountID, "source/unlisted.txt", filter)
	if err != nil {
		t.Fatalf("direct read should be allowed: %v", err)
	}
	file.Close()
	entries, omitted, err := service.ManifestFiltered(context.Background(), mountID, "source", filter)
	if err != nil || len(entries) != 0 || omitted != 1 {
		t.Fatalf("manifest exposed unlisted file: entries=%+v omitted=%d err=%v", entries, omitted, err)
	}
}
