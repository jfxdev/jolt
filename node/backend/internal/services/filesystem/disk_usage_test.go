package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func canonicalDiskUsageTestPath(t *testing.T, name string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(name)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestDiskUsageAggregatesDirectoriesAndSortsByAllocatedBytes(t *testing.T) {
	service, mountID, root := newTestService(t, "read_only")
	root = canonicalDiskUsageTestPath(t, root)
	writeFile(t, filepath.Join(root, "small.txt"), "small")
	writeFile(t, filepath.Join(root, "media", "nested", "large.bin"), strings.Repeat("x", 256<<10))
	writeFile(t, filepath.Join(root, "media", "other.bin"), strings.Repeat("x", 16<<10))

	result, err := service.DiskUsage(context.Background(), mountID, "", DiskUsageOptions{})
	if err != nil {
		t.Fatalf("disk usage: %v", err)
	}
	if len(result.Entries) != 2 || result.Entries[0].Name != "media" {
		t.Fatalf("entries are not sorted by disk usage: %+v", result.Entries)
	}
	largeInfo, err := safeLstat(filepath.Join(root, "media", "nested", "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if large := allocatedBytes(largeInfo); large == 0 || result.Entries[0].DiskUsage < large {
		t.Fatalf("recursive directory usage = %d, large file = %d", result.Entries[0].DiskUsage, large)
	}
	var childrenTotal int64
	for _, entry := range result.Entries {
		childrenTotal += entry.DiskUsage
	}
	rootInfo, err := safeLstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalBytes != childrenTotal+allocatedBytes(rootInfo) {
		t.Fatalf("total = %d, children = %d, root = %d", result.TotalBytes, childrenTotal, allocatedBytes(rootInfo))
	}
	if result.Truncated || result.ReadErrors != 0 {
		t.Fatalf("complete scan reported incomplete state: %+v", result)
	}
}

func TestDiskUsageUsesAllocatedRatherThanApparentSize(t *testing.T) {
	service, mountID, root := newTestService(t, "read_only")
	root = canonicalDiskUsageTestPath(t, root)
	file, err := os.Create(filepath.Join(root, "sparse.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(1 << 30); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := service.DiskUsage(context.Background(), mountID, "", DiskUsageOptions{})
	if err != nil {
		t.Fatalf("disk usage: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("unexpected entries: %+v", result.Entries)
	}
	entry := result.Entries[0]
	if entry.Size != 1<<30 {
		t.Fatalf("apparent size = %d", entry.Size)
	}
	if entry.DiskUsage >= entry.Size {
		t.Fatalf("sparse file allocated %d bytes for apparent size %d", entry.DiskUsage, entry.Size)
	}
}

func TestDiskUsageDoesNotFollowSymlinksOrExposePartials(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	root = canonicalDiskUsageTestPath(t, root)
	outside := canonicalDiskUsageTestPath(t, t.TempDir())
	writeFile(t, filepath.Join(outside, "secret.bin"), strings.Repeat("x", 128<<10))
	if err := os.Symlink(outside, filepath.Join(root, "outside")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := service.AppendUpload(context.Background(), mountID, "pending.bin", "upl_usage", 0, 10,
		strings.NewReader("12345")); err != nil {
		t.Fatalf("partial upload: %v", err)
	}

	result, err := service.DiskUsage(context.Background(), mountID, "", DiskUsageOptions{})
	if err != nil {
		t.Fatalf("disk usage: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Name != "outside" || result.Entries[0].Type != "symlink" {
		t.Fatalf("unexpected entries: %+v", result.Entries)
	}
	outsideInfo, err := safeLstat(filepath.Join(outside, "secret.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries[0].DiskUsage >= allocatedBytes(outsideInfo) {
		t.Fatalf("symlink included its target: %+v", result.Entries[0])
	}
}

func TestDiskUsageReportsEntryLimit(t *testing.T) {
	service, mountID, root := newTestService(t, "read_only")
	root = canonicalDiskUsageTestPath(t, root)
	for _, name := range []string{"a", "b", "c"} {
		writeFile(t, filepath.Join(root, name), name)
	}
	result, err := service.DiskUsage(context.Background(), mountID, "", DiskUsageOptions{MaxEntries: 2})
	if err != nil {
		t.Fatalf("disk usage: %v", err)
	}
	if !result.Truncated || result.TruncatedReason != "entries" {
		t.Fatalf("entry limit was not reported: %+v", result)
	}
}

func TestDiskUsageRejectsFilesAndTraversal(t *testing.T) {
	service, mountID, root := newTestService(t, "read_only")
	root = canonicalDiskUsageTestPath(t, root)
	writeFile(t, filepath.Join(root, "file.txt"), "content")
	if _, err := service.DiskUsage(context.Background(), mountID, "file.txt", DiskUsageOptions{}); err == nil {
		t.Fatal("disk usage accepted a file as its root")
	}
	if _, err := service.DiskUsage(context.Background(), mountID, "../", DiskUsageOptions{}); err == nil {
		t.Fatal("disk usage escaped the mount")
	}
}
