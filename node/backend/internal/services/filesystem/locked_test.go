package filesystem

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// lockedFixture returns a service whose only mount is locked and holds one file
// and one directory on disk.
func lockedFixture(t *testing.T) (*Service, string, string) {
	t.Helper()
	service, mountID, root := newTestService(t, "read_write")
	ctx := context.Background()
	mount, err := service.GetMount(ctx, mountID)
	if err != nil {
		t.Fatal(err)
	}
	mount.Locked = true
	if _, err := service.SaveMount(ctx, mount); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "a.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	return service, mountID, root
}

func TestLockedMountKeepsMetadataAvailable(t *testing.T) {
	service, mountID, _ := lockedFixture(t)
	ctx := context.Background()
	if mount, err := service.GetMount(ctx, mountID); err != nil || !mount.Locked {
		t.Fatalf("mount = %+v, %v", mount, err)
	}
	if page, err := service.ListPage(ctx, mountID, "docs", 100, ""); err != nil || len(page.Items) != 1 {
		t.Fatalf("list: %+v, %v", page, err)
	}
	if entries, err := service.List(ctx, mountID, "docs", 100); err != nil || len(entries) != 1 {
		t.Fatalf("list: %+v, %v", entries, err)
	}
	if entry, err := service.Metadata(ctx, mountID, "docs/a.txt"); err != nil || entry.Size != int64(len("secret")) {
		t.Fatalf("metadata: %+v, %v", entry, err)
	}
	if _, err := service.Search(ctx, mountID, "", SearchOptions{Query: "a"}); err != nil {
		t.Fatalf("search: %v", err)
	}
	if _, err := service.DiskUsage(ctx, mountID, "", DiskUsageOptions{}); err != nil {
		t.Fatalf("disk usage: %v", err)
	}
}

func TestLockedMountRefusesContentAndMovement(t *testing.T) {
	service, mountID, root := lockedFixture(t)
	ctx := context.Background()
	check := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrLocked) {
			t.Fatalf("%s: err = %v, want ErrLocked", name, err)
		}
	}

	file, _, err := service.Open(ctx, mountID, "docs/a.txt")
	if file != nil {
		file.Close()
	}
	check("open", err)
	_, err = service.Checksum(ctx, mountID, "docs/a.txt")
	check("checksum", err)
	_, err = service.PlanArchive(ctx, mountID, "docs", ArchiveOptions{})
	check("archive plan", err)
	_, err = service.Archive(ctx, mountID, "docs", ArchiveOptions{}, io.Discard)
	check("archive", err)

	_, err = service.Upload(ctx, mountID, "docs/new.txt", strings.NewReader("x"), false)
	check("upload", err)
	check("mkdir", service.CreateDirectory(ctx, mountID, "docs/sub"))
	check("delete", service.Delete(ctx, mountID, "docs/a.txt", false))
	check("rename", service.Move(ctx, mountID, "docs/a.txt", "docs/b.txt", false))
	_, err = service.Copy(ctx, mountID, "docs/a.txt", "docs/c.txt", false)
	check("copy", err)
	_, _, err = service.CopyFileVerified(ctx, mountID, "docs/a.txt", "docs/d.txt", false, "", false, nil)
	check("verified copy", err)
	_, _, err = service.CopyFileResumable(ctx, mountID, "docs/a.txt", "docs/e.txt", "key", false, 0, 1024, "", false, nil)
	check("resumable copy", err)
	check("validate move source", service.ValidateMoveSource(ctx, mountID, "docs/a.txt"))
	_, err = service.UploadBlocks(ctx, entities.UploadSession{MountID: mountID, Destination: "docs/a.txt"}, 0, 10)
	check("upload blocks", err)

	// Nothing was changed or created on disk.
	if data, err := os.ReadFile(filepath.Join(root, "docs", "a.txt")); err != nil || string(data) != "secret" {
		t.Fatalf("file changed: %q, %v", data, err)
	}
	for _, name := range []string{"new.txt", "b.txt", "c.txt", "d.txt", "e.txt", "sub"} {
		if _, err := os.Stat(filepath.Join(root, "docs", name)); !os.IsNotExist(err) {
			t.Fatalf("%s exists after a refused operation: %v", name, err)
		}
	}
}

func TestIsLocked(t *testing.T) {
	service, mountID, _ := lockedFixture(t)
	ctx := context.Background()
	if locked, err := service.IsLocked(ctx, mountID); err != nil || !locked {
		t.Fatalf("locked mount: %v, %v", locked, err)
	}
	if locked, err := service.IsLocked(ctx, "missing"); err != nil || locked {
		t.Fatalf("missing mount must not read as locked: %v, %v", locked, err)
	}
	open, openID, _ := newTestService(t, "read_write")
	if locked, err := open.IsLocked(ctx, openID); err != nil || locked {
		t.Fatalf("regular mount: %v, %v", locked, err)
	}
}
