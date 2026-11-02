package filesystem

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/filetypes"
)

func testAccessFilter(t *testing.T) *AccessFilter {
	t.Helper()
	base := "nodes/n/files/mounts/m"
	filter, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"read", "list"}},
		{PolicyID: "hidden", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "blocked", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"lock"}}, Visibility: "visible"},
		{PolicyID: "write-deny", Path: base + "/**", Capabilities: []string{"deny", "write"}, FileTypes: &filetypes.Selector{Extensions: []string{"txt"}}},
		{PolicyID: "private", Path: base + "/private/**", Capabilities: []string{"deny"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	access, err := NewAccessFilter(filter, base)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func TestAccessFilterReadTreesBeforePaginationAndCounting(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	for name, data := range map[string]string{
		"good.txt": "public", "secret.pem": "-----BEGIN PRIVATE KEY-----", "blocked.lock": "blocked",
		"folder/movie.mp4": "video", "folder/secondary.pem": "hidden", "private/hidden.txt": "private",
	} {
		writeFile(t, filepath.Join(root, filepath.FromSlash(name)), data)
	}
	filter := testAccessFilter(t)
	ctx := context.Background()
	var names []string
	after := ""
	blocked := false
	for {
		page, err := service.ListPageFiltered(ctx, mountID, "", 1, after, filter)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			names = append(names, item.Name)
			if item.Name == "blocked.lock" {
				blocked = item.Blocked
			}
		}
		if !page.HasMore {
			break
		}
		if page.NextAfter == "" || page.NextAfter == after {
			t.Fatal("invalid cursor")
		}
		after = page.NextAfter
	}
	sort.Strings(names)
	if len(names) != 3 || names[0] != "blocked.lock" || names[1] != "folder" || names[2] != "good.txt" || !blocked {
		t.Fatalf("listing = %v blocked=%t", names, blocked)
	}
	search, err := service.Search(ctx, mountID, "", SearchOptions{Query: ".", Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, item := range search.Entries {
		found = append(found, item.Path)
		if item.Path == "blocked.lock" && !item.Blocked {
			t.Fatal("search omitted blocked flag")
		}
	}
	sort.Strings(found)
	if len(found) != 3 || found[0] != "blocked.lock" || found[1] != "folder/movie.mp4" || found[2] != "good.txt" {
		t.Fatalf("search = %v", found)
	}
	usage, err := service.DiskUsage(ctx, mountID, "", DiskUsageOptions{Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range usage.Entries {
		if item.Name != "folder" && item.Name != "good.txt" {
			t.Fatalf("blocked item counted in usage: %+v", item)
		}
	}
	if len(usage.Entries) != 2 {
		t.Fatalf("usage entries = %+v", usage.Entries)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	var expectedUsage int64
	for _, name := range []string{".", "good.txt", "folder", "folder/movie.mp4"} {
		info, err := safeLstat(filepath.Join(canonicalRoot, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		expectedUsage += allocatedBytes(info)
	}
	if usage.TotalBytes != expectedUsage {
		t.Fatalf("usage included inaccessible bytes: got %d want %d", usage.TotalBytes, expectedUsage)
	}
	plan, err := service.PlanArchive(ctx, mountID, "", ArchiveOptions{Filter: filter, ScanSecrets: true})
	if err != nil || plan.Entries != 2 || plan.Bytes != int64(len("public")+len("video")) {
		t.Fatalf("archive plan=%+v err=%v", plan, err)
	}
	var output bytes.Buffer
	if _, err := service.Archive(ctx, mountID, "", ArchiveOptions{Filter: filter, ScanSecrets: true}, &output); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, item := range archive.File {
		if item.FileInfo().IsDir() {
			continue
		}
		files = append(files, item.Name)
		reader, err := item.Open()
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(files)
	if len(files) != 2 || files[0] != "folder/movie.mp4" || files[1] != "good.txt" {
		t.Fatalf("archive files = %v", files)
	}
	if _, err := service.ListPageFiltered(ctx, mountID, "private", 10, "", filter); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("private root: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "blocked.lock"))
	if err != nil || !errors.Is(filter.checkRoot("blocked.lock", info), ErrFilteredBlocked) {
		t.Fatalf("blocked root: %v", err)
	}
	if _, err := service.ListPageFiltered(ctx, mountID, "", 10, "", &AccessFilter{}); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("invalid filter did not fail closed: %v", err)
	}
}

func TestAccessFilterDirectoryTypeAndVisibleBlockedTree(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "album.pem", "inside.txt"), "allowed")
	writeFile(t, filepath.Join(root, "locked", "inside.txt"), "restricted")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"read", "list"}},
		{PolicyID: "extension", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "locked", Path: base + "/locked/**", Capabilities: []string{"deny"}, Visibility: "visible"},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	page, err := service.ListPageFiltered(ctx, mountID, "", 10, "", filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("listing = %+v", page.Items)
	}
	for _, item := range page.Items {
		if item.Name == "album.pem" && item.Blocked {
			t.Fatal("directory was treated as a file")
		}
		if item.Name == "locked" && !item.Blocked {
			t.Fatal("denied directory was not marked blocked")
		}
	}
	if _, err := service.ListPageFiltered(ctx, mountID, "locked", 10, "", filter); !errors.Is(err, ErrFilteredBlocked) {
		t.Fatalf("locked directory: %v", err)
	}
	search, err := service.Search(ctx, mountID, "", SearchOptions{Query: ".", Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	if len(search.Entries) != 2 || search.Entries[0].Path != "album.pem" || search.Entries[1].Path != "album.pem/inside.txt" {
		t.Fatalf("search = %+v", search.Entries)
	}
	plan, err := service.PlanArchive(ctx, mountID, "", ArchiveOptions{Filter: filter})
	if err != nil || plan.Entries != 1 || plan.Bytes != int64(len("allowed")) {
		t.Fatalf("archive plan = %+v, err = %v", plan, err)
	}
	usage, err := service.DiskUsage(ctx, mountID, "", DiskUsageOptions{Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	if len(usage.Entries) != 1 || usage.Entries[0].Name != "album.pem" {
		t.Fatalf("usage = %+v", usage.Entries)
	}
}

func TestAccessFilterDirectAccessAndDeniedAncestor(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	for _, name := range []string{"plain.txt", "secret.pem", "blocked.lock", "locked/child.txt", "locked/nested/child.txt"} {
		writeFile(t, filepath.Join(root, name), "content")
	}
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read"}},
		{PolicyID: "hidden", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "blocked", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"lock"}}, Visibility: "visible"},
		{PolicyID: "directory", Path: base + "/locked", Capabilities: []string{"deny", "list"}, Visibility: "visible"},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	file, _, err := service.OpenFiltered(ctx, mountID, "plain.txt", filter)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	for name, expected := range map[string]error{"secret.pem": ErrFilteredHidden, "blocked.lock": ErrFilteredBlocked, "locked/child.txt": ErrFilteredHidden, "locked/nested/child.txt": ErrFilteredHidden} {
		f, _, err := service.OpenFiltered(ctx, mountID, name, filter)
		if f != nil {
			f.Close()
		}
		if !errors.Is(err, expected) {
			t.Errorf("open %s: got %v, want %v", name, err, expected)
		}
	}
	if _, err := service.ListPageFiltered(ctx, mountID, "locked/nested", 10, "", filter); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("list denied ancestor: %v", err)
	}
	if _, err := service.Search(ctx, mountID, "locked/nested", SearchOptions{Query: ".", Filter: filter}); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("search denied ancestor: %v", err)
	}
	if _, err := service.DiskUsage(ctx, mountID, "locked/nested", DiskUsageOptions{Filter: filter}); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("usage denied ancestor: %v", err)
	}
	var archive bytes.Buffer
	if _, err := service.Archive(ctx, mountID, "locked/nested", ArchiveOptions{Filter: filter}, &archive); !errors.Is(err, ErrFilteredHidden) || archive.Len() != 0 {
		t.Fatalf("archive denied ancestor: %v, %d bytes", err, archive.Len())
	}
}

func TestAccessFilterNarrowGrantDoesNotRequireParentListing(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "nested", "allowed.txt"), "content")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "narrow", Path: base + "/nested/allowed.txt", Capabilities: []string{"read", "list"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := service.OpenFiltered(context.Background(), mountID, "nested/allowed.txt", filter)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
}

func TestDeleteFilteredPreflightsCompleteTree(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	for _, tc := range []struct {
		name          string
		protectedRule filetypes.Rule
	}{
		{"hidden file", filetypes.Rule{PolicyID: "hidden", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}},
		{"delete denied", filetypes.Rule{PolicyID: "deny-delete", Path: base + "/tree/nested/secret.pem", Capabilities: []string{"deny", "delete"}}},
		{"parent denied", filetypes.Rule{PolicyID: "deny-dir", Path: base + "/tree/nested", Capabilities: []string{"deny", "list"}, Visibility: "visible"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, mountID, root := newTestService(t, "read_write")
			writeFile(t, filepath.Join(root, "tree", "public.txt"), "public")
			writeFile(t, filepath.Join(root, "tree", "nested", "secret.pem"), "secret")
			compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
				{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"read", "list", "delete"}}, tc.protectedRule,
			}}).Compile()
			if err != nil {
				t.Fatal(err)
			}
			filter, err := NewAccessFilter(compiled, base)
			if err != nil {
				t.Fatal(err)
			}
			if err := service.DeleteFiltered(context.Background(), mountID, "tree", true, filter); !errors.Is(err, ErrProtectedTree) {
				t.Fatalf("delete: %v", err)
			}
			for _, name := range []string{"public.txt", "nested/secret.pem"} {
				if _, err := os.Stat(filepath.Join(root, "tree", name)); err != nil {
					t.Fatalf("preflight changed %s: %v", name, err)
				}
			}
		})
	}
	t.Run("allowed", func(t *testing.T) {
		service, mountID, root := newTestService(t, "read_write")
		writeFile(t, filepath.Join(root, "tree", "nested", "public.txt"), "public")
		compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
			{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"read", "list", "delete"}},
		}}).Compile()
		if err != nil {
			t.Fatal(err)
		}
		filter, err := NewAccessFilter(compiled, base)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.DeleteFiltered(context.Background(), mountID, "tree", true, filter); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, "tree")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("tree remains: %v", err)
		}
	})
}

func TestDeleteFilteredFailsClosedOnCancellationAndSymlink(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "tree", "file.txt"), "public")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"read", "list", "delete"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.DeleteFiltered(ctx, mountID, "tree", true, filter); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delete: %v", err)
	}
	if err := os.Symlink("file.txt", filepath.Join(root, "tree", "link")); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteFiltered(context.Background(), mountID, "tree", true, filter); !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("symlink delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "tree", "file.txt")); err != nil {
		t.Fatalf("file changed: %v", err)
	}
}

func TestMoveFilteredPreflightsSourceAndDestination(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	cases := []struct {
		name        string
		source      string
		destination string
		overwrite   bool
		rule        filetypes.Rule
	}{
		{"protected source", "source", "target", false, filetypes.Rule{PolicyID: "deny-source", Path: base + "/source/nested/secret.txt", Capabilities: []string{"deny", "update"}}},
		{"destination child", "source", "target", false, filetypes.Rule{PolicyID: "deny-destination", Path: base + "/target/nested/secret.txt", Capabilities: []string{"deny", "create"}}},
		{"destination extension", "source/nested/secret.txt", "new.pem", false, filetypes.Rule{PolicyID: "deny-extension", Path: base + "/**", Capabilities: []string{"deny", "create"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}},
		{"overwrite protected child", "source", "existing", true, filetypes.Rule{PolicyID: "deny-existing", Path: base + "/existing/restricted.txt", Capabilities: []string{"deny", "read"}}},
		{"overwrite update denied", "source", "existing", true, filetypes.Rule{PolicyID: "deny-update", Path: base + "/existing/restricted.txt", Capabilities: []string{"deny", "update"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, mountID, root := newTestService(t, "read_write")
			writeFile(t, filepath.Join(root, "source", "nested", "secret.txt"), "source")
			writeFile(t, filepath.Join(root, "existing", "restricted.txt"), "destination")
			compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
				{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}, tc.rule,
			}}).Compile()
			if err != nil {
				t.Fatal(err)
			}
			filter, err := NewAccessFilter(compiled, base)
			if err != nil {
				t.Fatal(err)
			}
			err = service.MoveFiltered(context.Background(), mountID, tc.source, tc.destination, tc.overwrite, filter)
			if !errors.Is(err, ErrProtectedTree) && !errors.Is(err, ErrFilteredBlocked) && !errors.Is(err, ErrFilteredHidden) {
				t.Fatalf("move: %v", err)
			}
			for name, want := range map[string]string{"source/nested/secret.txt": "source", "existing/restricted.txt": "destination"} {
				got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
				if err != nil || string(got) != want {
					t.Fatalf("%s changed: %q %v", name, got, err)
				}
			}
			if tc.destination != "existing" {
				if _, err := os.Lstat(filepath.Join(root, tc.destination)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("destination created: %v", err)
				}
			}
		})
	}
	t.Run("allowed overwrite", func(t *testing.T) {
		service, mountID, root := newTestService(t, "read_write")
		writeFile(t, filepath.Join(root, "source", "nested.txt"), "new")
		writeFile(t, filepath.Join(root, "existing", "old.txt"), "old")
		compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}}).Compile()
		if err != nil {
			t.Fatal(err)
		}
		filter, err := NewAccessFilter(compiled, base)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.MoveFiltered(context.Background(), mountID, "source", "existing", true, filter); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(root, "existing", "nested.txt"))
		if err != nil || string(got) != "new" {
			t.Fatalf("destination: %q %v", got, err)
		}
		if _, err := os.Stat(filepath.Join(root, "source")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source remains: %v", err)
		}
	})
}

func TestMoveFilteredDeniedDestinationAncestorAndCancellation(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source.txt"), "content")
	writeFile(t, filepath.Join(root, "locked", "keep.txt"), "keep")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}},
		{PolicyID: "deny-parent", Path: base + "/locked", Capabilities: []string{"deny", "list"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.MoveFiltered(context.Background(), mountID, "source.txt", "locked/new.txt", false, filter); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("denied parent: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.MoveFiltered(ctx, mountID, "source.txt", "target.txt", false, filter); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "source.txt")); err != nil || string(got) != "content" {
		t.Fatalf("source changed: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "locked", "new.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination created: %v", err)
	}
}

func TestCopyFileFilteredAuthorization(t *testing.T) {
	base := "nodes/n/files/mounts/m"
	cases := []struct {
		name, source, destination string
		overwrite                 bool
		rule                      filetypes.Rule
	}{
		{"source hidden", "secret.pem", "new.txt", false, filetypes.Rule{PolicyID: "deny-read", Path: base + "/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}},
		{"target extension", "source.txt", "new.pem", false, filetypes.Rule{PolicyID: "deny-create", Path: base + "/**", Capabilities: []string{"deny", "create"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}}},
		{"overwrite denied", "source.txt", "existing.txt", true, filetypes.Rule{PolicyID: "deny-update", Path: base + "/existing.txt", Capabilities: []string{"deny", "update"}}},
		{"hidden target", "source.txt", "existing.txt", true, filetypes.Rule{PolicyID: "deny-target", Path: base + "/existing.txt", Capabilities: []string{"deny", "read"}}},
		{"parent denied", "source.txt", "locked/new.txt", false, filetypes.Rule{PolicyID: "deny-parent", Path: base + "/locked", Capabilities: []string{"deny", "list"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, mountID, root := newTestService(t, "read_write")
			writeFile(t, filepath.Join(root, "source.txt"), "source")
			writeFile(t, filepath.Join(root, "secret.pem"), "secret")
			writeFile(t, filepath.Join(root, "existing.txt"), "existing")
			writeFile(t, filepath.Join(root, "locked", "keep.txt"), "keep")
			compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}, tc.rule}}).Compile()
			if err != nil {
				t.Fatal(err)
			}
			filter, err := NewAccessFilter(compiled, base)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.CopyFileFiltered(context.Background(), mountID, tc.source, tc.destination, tc.overwrite, filter)
			if !errors.Is(err, ErrFilteredHidden) && !errors.Is(err, ErrFilteredBlocked) {
				t.Fatalf("copy: %v", err)
			}
			if got, err := os.ReadFile(filepath.Join(root, "existing.txt")); err != nil || string(got) != "existing" {
				t.Fatalf("existing changed: %q %v", got, err)
			}
			if tc.destination != "existing.txt" {
				if _, err := os.Lstat(filepath.Join(root, tc.destination)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("destination created: %v", err)
				}
			}
		})
	}
	t.Run("allowed overwrite", func(t *testing.T) {
		service, mountID, root := newTestService(t, "read_write")
		writeFile(t, filepath.Join(root, "source.txt"), "new")
		writeFile(t, filepath.Join(root, "existing.txt"), "old")
		compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}}).Compile()
		if err != nil {
			t.Fatal(err)
		}
		filter, err := NewAccessFilter(compiled, base)
		if err != nil {
			t.Fatal(err)
		}
		n, err := service.CopyFileFiltered(context.Background(), mountID, "source.txt", "existing.txt", true, filter)
		if err != nil || n != 3 {
			t.Fatalf("copy: %d %v", n, err)
		}
		if got, err := os.ReadFile(filepath.Join(root, "existing.txt")); err != nil || string(got) != "new" {
			t.Fatalf("destination: %q %v", got, err)
		}
	})
}

func TestCopyFileFilteredRechecksDestinationBeforePublish(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mount, destination, err := service.resolve(ctx, mountID, "target.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFilteredFileDestination(ctx, mount, destination, false, filter); err != nil {
		t.Fatal(err)
	}
	check := func() error {
		if err := os.WriteFile(destination, []byte("concurrent"), 0o600); err != nil {
			return err
		}
		return validateFilteredFileDestination(ctx, mount, destination, false, filter)
	}
	_, err = copyAtomicWithCheck(ctx, mount, strings.NewReader("source"), destination, false, 6, 0, nil, check)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("publish: %v", err)
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != "concurrent" {
		t.Fatalf("concurrent destination changed: %q %v", got, err)
	}
}

func TestCopyFileFilteredNeverRemovesNewDestinationDirectory(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	ctx := context.Background()
	mount, destination, err := service.resolve(ctx, mountID, "target", true)
	if err != nil {
		t.Fatal(err)
	}
	check := func() error {
		if err := os.Mkdir(destination, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destination, "keep"), []byte("safe"), 0o600)
	}
	_, err = copyAtomicWithCheck(ctx, mount, strings.NewReader("source"), destination, true, 6, 0, nil, check)
	if !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("publish: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "keep")); err != nil || string(got) != "safe" {
		t.Fatalf("destination changed: %q %v", got, err)
	}
}

func TestCopyTreeFilteredSelectsOnlyAuthorizedEntries(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	for name, content := range map[string]string{
		"source/good.txt": "good", "source/secret.pem": "secret", "source/nested/allowed.txt": "allowed",
		"source/nested/denied.txt": "denied", "source/private/child.txt": "private",
		"target/nested/denied.txt": "existing",
	} {
		writeFile(t, filepath.Join(root, filepath.FromSlash(name)), content)
	}
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}},
		{PolicyID: "secret", Path: base + "/source/**", Capabilities: []string{"deny", "read"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "private", Path: base + "/source/private/**", Capabilities: []string{"deny", "list"}},
		{PolicyID: "deny-target", Path: base + "/target/nested/denied.txt", Capabilities: []string{"deny", "update"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	n, err := service.CopyTreeFiltered(context.Background(), mountID, "source", "target", true, filter)
	if err != nil || n != int64(len("good")+len("allowed")) {
		t.Fatalf("copy: %d %v", n, err)
	}
	for name, want := range map[string]string{"good.txt": "good", "nested/allowed.txt": "allowed", "nested/denied.txt": "existing"} {
		got, err := os.ReadFile(filepath.Join(root, "target", filepath.FromSlash(name)))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	for _, name := range []string{"secret.pem", "private"} {
		if _, err := os.Lstat(filepath.Join(root, "target", name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restricted item copied: %s, %v", name, err)
		}
	}
}

func TestCopyTreeFilteredSkipsDeniedDestinationDirectoryAndSymlink(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source", "allowed.txt"), "allowed")
	writeFile(t, filepath.Join(root, "source", "restricted", "child.txt"), "restricted")
	if err := os.Symlink("allowed.txt", filepath.Join(root, "source", "link")); err != nil {
		t.Fatal(err)
	}
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}},
		{PolicyID: "deny-dir", Path: base + "/target/restricted", Capabilities: []string{"deny", "create"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	n, err := service.CopyTreeFiltered(context.Background(), mountID, "source", "target", false, filter)
	if err != nil || n != int64(len("allowed")) {
		t.Fatalf("copy: %d %v", n, err)
	}
	for _, name := range []string{"restricted", "link"} {
		if _, err := os.Lstat(filepath.Join(root, "target", name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected target %s: %v", name, err)
		}
	}
}

func TestCopyTreeFilteredRejectsDestinationInsideSource(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source", "file.txt"), "source")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CopyTreeFiltered(context.Background(), mountID, "source", "source/copy", false, filter); !errors.Is(err, ErrInvalid) {
		t.Fatalf("copy inside source: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "source", "copy")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination created: %v", err)
	}
}

type testUploadReader struct {
	reader *strings.Reader
	first  func() error
}

func (r *testUploadReader) Read(p []byte) (int, error) {
	if r.first != nil {
		fn := r.first
		r.first = nil
		if err := fn(); err != nil {
			return 0, err
		}
	}
	return r.reader.Read(p)
}

func TestUploadFilteredAuthorizationAndPublication(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "existing.txt"), "existing")
	writeFile(t, filepath.Join(root, "locked", "keep.txt"), "keep")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}},
		{PolicyID: "deny-create", Path: base + "/**", Capabilities: []string{"deny", "create"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "deny-update", Path: base + "/existing.txt", Capabilities: []string{"deny", "update"}},
		{PolicyID: "deny-parent", Path: base + "/locked", Capabilities: []string{"deny", "list"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, tc := range []struct {
		path      string
		overwrite bool
		want      error
	}{
		{"blocked.pem", false, ErrFilteredBlocked}, {"existing.txt", true, ErrFilteredBlocked}, {"locked/new.txt", false, ErrFilteredHidden},
	} {
		read := false
		body := &testUploadReader{reader: strings.NewReader("new"), first: func() error { read = true; return nil }}
		if _, err := service.UploadFiltered(ctx, mountID, tc.path, body, tc.overwrite, filter); !errors.Is(err, tc.want) || read {
			t.Fatalf("upload %s: err=%v read=%t", tc.path, err, read)
		}
	}
	body := &testUploadReader{reader: strings.NewReader("new"), first: func() error { return os.WriteFile(filepath.Join(root, "concurrent.txt"), []byte("other"), 0o600) }}
	if _, err := service.UploadFiltered(ctx, mountID, "concurrent.txt", body, false, filter); !errors.Is(err, ErrConflict) {
		t.Fatalf("revalidation: %v", err)
	}
	for name, want := range map[string]string{"existing.txt": "existing", "concurrent.txt": "other"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	if n, err := service.UploadFiltered(ctx, mountID, "allowed.txt", strings.NewReader("new"), false, filter); err != nil || n != 3 {
		t.Fatalf("allowed: %d %v", n, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "allowed.txt")); err != nil || string(got) != "new" {
		t.Fatalf("allowed destination: %q %v", got, err)
	}
	matches, err := filepath.Glob(filepath.Join(root, ".jolt-*.partial"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("partials: %v, %v", matches, err)
	}
}

func TestResumableUploadFilteredRevalidatesPersistedDestination(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	base := "nodes/n/files/mounts/m"
	makeFilter := func(deny string) *AccessFilter {
		rules := []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}
		if deny != "" {
			rules = append(rules, filetypes.Rule{PolicyID: "deny", Path: base + "/**", Capabilities: []string{"deny", deny}, FileTypes: &filetypes.Selector{Extensions: []string{"txt"}}})
		}
		compiled, err := (filetypes.Context{Version: 1, Rules: rules}).Compile()
		if err != nil {
			t.Fatal(err)
		}
		filter, err := NewAccessFilter(compiled, base)
		if err != nil {
			t.Fatal(err)
		}
		return filter
	}
	ctx := context.Background()
	session := entities.UploadSession{ID: "upl_session", MountID: mountID, Destination: "file.txt", Size: 6}
	allow, deny := makeFilter(""), makeFilter("create")
	if err := service.ValidateUploadDestinationFiltered(ctx, session, deny); !errors.Is(err, ErrFilteredBlocked) {
		t.Fatalf("denied admission: %v", err)
	}
	if err := service.ValidateUploadDestinationFiltered(ctx, session, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing context: %v", err)
	}
	if offset, err := service.AppendUploadFiltered(ctx, session, 0, strings.NewReader("abc"), allow); err != nil || offset != 3 {
		t.Fatalf("first chunk %d: %v", offset, err)
	}
	read := false
	body := &testUploadReader{reader: strings.NewReader("def"), first: func() error { read = true; return nil }}
	if _, err := service.AppendUploadFiltered(ctx, session, 3, body, deny); !errors.Is(err, ErrFilteredBlocked) || read {
		t.Fatalf("denied resume: %v read=%v", err, read)
	}
	if offset, err := service.AppendUploadFiltered(ctx, session, 3, strings.NewReader("def"), allow); err != nil || offset != 6 {
		t.Fatalf("resume %d: %v", offset, err)
	}
	if _, err := service.PrepareUploadFiltered(ctx, session, deny); !errors.Is(err, ErrFilteredBlocked) {
		t.Fatalf("denied preparation: %v", err)
	}
	if digest, err := service.PrepareUploadFiltered(ctx, session, allow); err != nil || len(digest) != 64 {
		t.Fatalf("allowed preparation: %q %v", digest, err)
	}
	if _, _, err := service.CompleteUploadFiltered(ctx, session, "", deny); !errors.Is(err, ErrFilteredBlocked) {
		t.Fatalf("denied publication: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "file.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination created: %v", err)
	}
	writeFile(t, filepath.Join(root, "file.txt"), "other")
	if _, _, err := service.CompleteUploadFiltered(ctx, session, "", allow); !errors.Is(err, ErrConflict) {
		t.Fatalf("concurrent destination: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "file.txt")); err != nil || string(data) != "other" {
		t.Fatalf("destination changed: %q %v", data, err)
	}
	if err := os.Remove(filepath.Join(root, "file.txt")); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := service.CompleteUploadFiltered(cancelled, session, "", allow); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled publication: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "file.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled upload published: %v", err)
	}
	if _, _, err := service.CompleteUploadFiltered(ctx, session, "", allow); err != nil {
		t.Fatalf("allowed publication: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "file.txt")); err != nil || string(data) != "abcdef" {
		t.Fatalf("published bytes: %q %v", data, err)
	}
	writeFile(t, filepath.Join(root, "overwrite.txt"), "original")
	overwrite := entities.UploadSession{ID: "upl_overwrite", MountID: mountID, Destination: "overwrite.txt", Size: 3, Overwrite: true}
	if _, err := service.AppendUploadFiltered(ctx, overwrite, 0, strings.NewReader("new"), allow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CompleteUploadFiltered(ctx, overwrite, "", makeFilter("update")); !errors.Is(err, ErrFilteredBlocked) {
		t.Fatalf("revoked overwrite: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "overwrite.txt")); err != nil || string(data) != "original" {
		t.Fatalf("overwrite destination changed: %q %v", data, err)
	}
}

func TestCreateDirectoryFilteredChecksRealTypeAndParent(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "locked", "keep.txt"), "keep")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{
		{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create"}},
		{PolicyID: "typed", Path: base + "/**", Capabilities: []string{"deny", "create"}, FileTypes: &filetypes.Selector{Extensions: []string{"pem"}}},
		{PolicyID: "parent", Path: base + "/locked", Capabilities: []string{"deny", "list"}},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CreateDirectoryFiltered(context.Background(), mountID, "folder.pem", filter); err != nil {
		t.Fatal(err)
	}
	if err := service.CreateDirectoryFiltered(context.Background(), mountID, "locked/new", filter); !errors.Is(err, ErrFilteredHidden) {
		t.Fatalf("parent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "locked", "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory created: %v", err)
	}
}

func TestUploadFilteredPreservesDirectoryCreatedDuringUpload(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	base := "nodes/n/files/mounts/m"
	compiled, err := (filetypes.Context{Version: 1, Rules: []filetypes.Rule{{PolicyID: "allow", Path: base + "/**", Capabilities: []string{"list", "read", "create", "update"}}}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := NewAccessFilter(compiled, base)
	if err != nil {
		t.Fatal(err)
	}
	body := &testUploadReader{reader: strings.NewReader("new"), first: func() error {
		if err := os.Mkdir(filepath.Join(root, "target"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, "target", "keep.txt"), []byte("keep"), 0o600)
	}}
	if _, err := service.UploadFiltered(context.Background(), mountID, "target", body, true, filter); !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("upload: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "target", "keep.txt")); err != nil || string(got) != "keep" {
		t.Fatalf("destination changed: %q %v", got, err)
	}
}
