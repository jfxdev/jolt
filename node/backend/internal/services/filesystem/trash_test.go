package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
	db "github.com/jfxdev/jolt/backend/internal/infra/state"
)

type trashFixture struct {
	service *Service
	store   *db.Store
	mountID string
	root    string
	now     time.Time
}

func newTrashFixture(t *testing.T, retentionDays int, extra ...func(*entities.Mount)) *trashFixture {
	t.Helper()
	root := t.TempDir()
	store, err := db.Open(filepath.Join(t.TempDir(), "state"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	f := &trashFixture{store: store, root: root, now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	f.service = New(store)
	f.service.now = func() time.Time { return f.now }
	mount := entities.Mount{Name: "m", LocalPath: root, Mode: "read_write", Published: true, Enabled: true, Trash: &entities.TrashConfig{Enabled: true, RetentionDays: retentionDays}}
	for _, option := range extra {
		option(&mount)
	}
	saved, err := f.service.SaveMount(context.Background(), mount)
	if err != nil {
		t.Fatal(err)
	}
	f.mountID = saved.ID
	return f
}

func (f *trashFixture) write(t *testing.T, name, content string) {
	t.Helper()
	target := filepath.Join(f.root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *trashFixture) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(f.root, filepath.FromSlash(name)))
	return err == nil
}

func (f *trashFixture) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDeleteMovesToTrashAndRestoreBringsItBack(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 30)
	f.write(t, "docs/report.txt", "quarterly")
	if err := f.service.Delete(ctx, f.mountID, "docs/report.txt", false); err != nil {
		t.Fatal(err)
	}
	if f.exists("docs/report.txt") {
		t.Fatal("the file is still where it was")
	}
	items, err := f.service.ListTrash(ctx, f.mountID)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	item := items[0]
	if item.Path != "docs/report.txt" || item.Type != "file" || item.Size != int64(len("quarterly")) || item.State != "stored" || item.ExpiresAt.Sub(item.DeletedAt) != 30*24*time.Hour {
		t.Fatalf("item %+v", item)
	}
	// The bytes are kept, under the id, and the folder is not reachable by name.
	if got := f.read(t, ".jolt-trash/"+item.ID+"/docs/report.txt"); got != "quarterly" {
		t.Fatalf("kept %q", got)
	}
	entries, err := f.service.List(ctx, f.mountID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name, "trash") {
			t.Fatalf("the trash is listed: %+v", entry)
		}
	}
	restored, err := f.service.RestoreTrash(ctx, f.mountID, item.ID)
	if err != nil || restored.ID != item.ID {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	if got := f.read(t, "docs/report.txt"); got != "quarterly" {
		t.Fatalf("restored %q", got)
	}
	if f.exists(".jolt-trash/" + item.ID) {
		t.Fatal("the trash folder of a restored entry was left")
	}
	if items, _ := f.service.ListTrash(ctx, f.mountID); len(items) != 0 {
		t.Fatalf("a restored entry is still listed: %+v", items)
	}
}

func TestADirectoryGoesToTrashWhole(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 7)
	f.write(t, "tree/a.txt", "a")
	f.write(t, "tree/sub/b.txt", "b")
	if err := f.service.Delete(ctx, f.mountID, "tree", true); err != nil {
		t.Fatal(err)
	}
	items, _ := f.service.ListTrash(ctx, f.mountID)
	if len(items) != 1 || items[0].Type != "directory" || items[0].ExpiresAt.Sub(items[0].DeletedAt) != 7*24*time.Hour {
		t.Fatalf("items %+v", items)
	}
	if _, err := f.service.RestoreTrash(ctx, f.mountID, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if f.read(t, "tree/sub/b.txt") != "b" || f.read(t, "tree/a.txt") != "a" {
		t.Fatal("the tree did not come back whole")
	}
}

func TestAnEmptyDirectoryAndTheMountRootAreNotTrashed(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 30)
	if err := os.Mkdir(filepath.Join(f.root, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.service.Delete(ctx, f.mountID, "empty", false); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.service.ListTrash(ctx, f.mountID); len(items) != 0 {
		t.Fatalf("an empty folder went to the trash: %+v", items)
	}
	if err := f.service.Delete(ctx, f.mountID, ".", true); err == nil {
		t.Fatal("the mount root was deleted")
	}
}

func TestRestoreRefusesAConflictAMissingParentAndAHiddenName(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 30)
	f.write(t, "a/file.txt", "old")
	if err := f.service.Delete(ctx, f.mountID, "a/file.txt", false); err != nil {
		t.Fatal(err)
	}
	items, _ := f.service.ListTrash(ctx, f.mountID)
	id := items[0].ID
	// Something new took the name: restoring must not overwrite it.
	f.write(t, "a/file.txt", "new")
	if _, err := f.service.RestoreTrash(ctx, f.mountID, id); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if f.read(t, "a/file.txt") != "new" {
		t.Fatal("restore overwrote the new file")
	}
	if err := os.Remove(filepath.Join(f.root, "a/file.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.root, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.RestoreTrash(ctx, f.mountID, id); err == nil {
		t.Fatal("restored into a folder that no longer exists")
	}
	if still, _ := f.service.ListTrash(ctx, f.mountID); len(still) != 1 {
		t.Fatalf("a refused restore dropped the entry: %+v", still)
	}
	if err := os.Mkdir(filepath.Join(f.root, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.RestoreTrash(ctx, f.mountID, id); err != nil {
		t.Fatalf("restore once the parent is back: %v", err)
	}
	// A name that has become hidden by configuration is not restored.
	g := newTrashFixture(t, 30)
	g.write(t, "x/secret.pem", "k")
	if err := g.service.Delete(ctx, g.mountID, "x/secret.pem", false); err != nil {
		t.Fatal(err)
	}
	mount, _ := g.service.GetMount(ctx, g.mountID)
	mount.HiddenPatterns = []string{"*.pem"}
	if _, err := g.service.SaveMount(ctx, mount); err != nil {
		t.Fatal(err)
	}
	gitems, _ := g.service.ListTrash(ctx, g.mountID)
	if _, err := g.service.RestoreTrash(ctx, g.mountID, gitems[0].ID); !errors.Is(err, ErrHiddenName) {
		t.Fatalf("hidden name: %v", err)
	}
}

func TestRestoreAndPurgeCheckTheMount(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 30)
	// A second mount in the same state: its id must not reach the first one's trash.
	other, err := f.service.SaveMount(ctx, entities.Mount{Name: "other", LocalPath: t.TempDir(), Mode: "read_write", Published: true, Enabled: true, Trash: &entities.TrashConfig{Enabled: true, RetentionDays: 30}})
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, "one.txt", "1")
	if err := f.service.Delete(ctx, f.mountID, "one.txt", false); err != nil {
		t.Fatal(err)
	}
	items, _ := f.service.ListTrash(ctx, f.mountID)
	// An id from another mount, or one that does not exist, is not found.
	if _, err := f.service.RestoreTrash(ctx, other.ID, items[0].ID); !errors.Is(err, ErrTrashNotFound) {
		t.Fatalf("foreign id: %v", err)
	}
	if _, err := f.service.PurgeTrash(ctx, other.ID, items[0].ID); !errors.Is(err, ErrTrashNotFound) {
		t.Fatalf("foreign purge: %v", err)
	}
	if !f.exists(".jolt-trash/" + items[0].ID) {
		t.Fatal("another mount purged this entry")
	}
	if _, err := f.service.PurgeTrash(ctx, f.mountID, "tr_0_000000000000"); !errors.Is(err, ErrTrashNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := f.service.PurgeTrash(ctx, f.mountID, "../../etc"); err == nil {
		t.Fatal("a path was accepted as an id")
	}
	if _, err := f.service.PurgeTrash(ctx, f.mountID, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if f.exists(".jolt-trash/" + items[0].ID) {
		t.Fatal("a purged entry was left on disk")
	}
	if _, err := f.service.RestoreTrash(ctx, f.mountID, items[0].ID); !errors.Is(err, ErrTrashNotFound) {
		t.Fatalf("restoring a purged entry: %v", err)
	}
}

func TestSweepPurgesOnlyWhatExpired(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 1)
	f.write(t, "old.txt", "o")
	if err := f.service.Delete(ctx, f.mountID, "old.txt", false); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(20 * time.Hour)
	f.write(t, "young.txt", "y")
	if err := f.service.Delete(ctx, f.mountID, "young.txt", false); err != nil {
		t.Fatal(err)
	}
	if purged, err := f.service.SweepTrash(ctx, f.now); err != nil || purged != 0 {
		t.Fatalf("early sweep: %d %v", purged, err)
	}
	// 5 hours later the first is past 24 h, the second is not.
	f.now = f.now.Add(5 * time.Hour)
	purged, err := f.service.SweepTrash(ctx, f.now)
	if err != nil || purged != 1 {
		t.Fatalf("sweep: %d %v", purged, err)
	}
	items, _ := f.service.ListTrash(ctx, f.mountID)
	if len(items) != 1 || items[0].Path != "young.txt" {
		t.Fatalf("kept %+v", items)
	}
}

func TestTrashIsRefusedOnAReadOnlyOrDisabledSetup(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 30)
	f.write(t, "keep.txt", "k")
	if err := f.service.Delete(ctx, f.mountID, ".jolt-trash/anything", true); err == nil {
		t.Fatal("the trash folder was addressable")
	}
	// Without trash a delete is permanent, as before.
	plain := newTrashFixture(t, 30, func(m *entities.Mount) { m.Trash = nil })
	plain.write(t, "gone.txt", "g")
	if err := plain.service.Delete(ctx, plain.mountID, "gone.txt", false); err != nil {
		t.Fatal(err)
	}
	if items, _ := plain.service.ListTrash(ctx, plain.mountID); len(items) != 0 || plain.exists(".jolt-trash") {
		t.Fatalf("a mount without trash kept something: %+v", items)
	}
	// A planted link in place of the folder is not followed.
	hostile := newTrashFixture(t, 30)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(hostile.root, ".jolt-trash")); err != nil {
		t.Fatal(err)
	}
	hostile.write(t, "victim.txt", "v")
	if err := hostile.service.Delete(ctx, hostile.mountID, "victim.txt", false); !errors.Is(err, ErrTrashUnavailable) {
		t.Fatalf("hostile trash folder: %v", err)
	}
	if !hostile.exists("victim.txt") {
		t.Fatal("a failed trash move lost the file")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("something was written outside the mount: %v", entries)
	}
	if items, _ := hostile.service.ListTrash(ctx, hostile.mountID); len(items) != 0 {
		t.Fatalf("a failed move left a record: %+v", items)
	}
}

func TestRecoveryReconcilesRecordsWithTheFolder(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 30)
	f.write(t, "moved.txt", "m")
	if err := f.service.Delete(ctx, f.mountID, "moved.txt", false); err != nil {
		t.Fatal(err)
	}
	items, _ := f.service.ListTrash(ctx, f.mountID)
	moved := items[0]
	put := func(item entities.TrashItem) {
		t.Helper()
		if err := f.store.PutTrashItem(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	// Crashed after the rename, before the record said so.
	crashedAfter := moved
	crashedAfter.State = "moving"
	put(crashedAfter)
	// Crashed before the rename: the file is still where it was.
	f.write(t, "stayed.txt", "s")
	before := entities.TrashItem{ID: "tr_1_aaaaaaaaaaaa", MountID: f.mountID, Path: "stayed.txt", Type: "file", State: "moving", DeletedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	put(before)
	// A purge that was interrupted.
	f.write(t, ".jolt-trash/tr_2_bbbbbbbbbbbb/half.txt", "h")
	purging := entities.TrashItem{ID: "tr_2_bbbbbbbbbbbb", MountID: f.mountID, Path: "half.txt", Type: "file", State: "purging", DeletedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	put(purging)
	// A record whose entry vanished from the host.
	gone := entities.TrashItem{ID: "tr_3_cccccccccccc", MountID: f.mountID, Path: "ghost.txt", Type: "file", State: "stored", DeletedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	put(gone)
	changed, err := f.service.RecoverTrash(ctx)
	if err != nil || changed != 4 {
		t.Fatalf("recover: %d %v", changed, err)
	}
	left, _ := f.service.ListTrash(ctx, f.mountID)
	if len(left) != 1 || left[0].ID != moved.ID || left[0].State != "stored" {
		t.Fatalf("after recovery %+v", left)
	}
	all, _ := f.store.AllTrashItems(ctx)
	if len(all) != 1 {
		t.Fatalf("stray records remain: %+v", all)
	}
	if f.exists(".jolt-trash/tr_2_bbbbbbbbbbbb") || !f.exists("stayed.txt") {
		t.Fatal("recovery removed the wrong thing")
	}
	// Recovering again changes nothing.
	if changed, err := f.service.RecoverTrash(ctx); err != nil || changed != 0 {
		t.Fatalf("second recovery: %d %v", changed, err)
	}
}

func TestRecoveryLeavesAnUnreachableMountAlone(t *testing.T) {
	ctx := context.Background()
	f := newTrashFixture(t, 30)
	f.write(t, "keep.txt", "k")
	if err := f.service.Delete(ctx, f.mountID, "keep.txt", false); err != nil {
		t.Fatal(err)
	}
	// The disk is not mounted: the whole mount directory is gone for now.
	hidden := f.root + ".away"
	if err := os.Rename(f.root, hidden); err != nil {
		t.Fatal(err)
	}
	if changed, err := f.service.RecoverTrash(ctx); err != nil || changed != 0 {
		t.Fatalf("recovery touched an unreachable mount: %d %v", changed, err)
	}
	if err := os.Rename(hidden, f.root); err != nil {
		t.Fatal(err)
	}
	if items, _ := f.service.ListTrash(ctx, f.mountID); len(items) != 1 {
		t.Fatalf("the records were lost with the disk: %+v", items)
	}
}
