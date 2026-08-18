package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
)

type parallelProbeLimiter struct {
	mu      sync.Mutex
	current int
	maximum int
	gate    chan struct{}
	once    sync.Once
}

func (l *parallelProbeLimiter) Wait(ctx context.Context, _ int64) error {
	l.mu.Lock()
	l.current++
	if l.current > l.maximum {
		l.maximum = l.current
	}
	if l.current >= 3 {
		l.once.Do(func() { close(l.gate) })
	}
	l.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.gate:
	}
	l.mu.Lock()
	l.current--
	l.mu.Unlock()
	return nil
}

func newTestService(t *testing.T, mode string) (*Service, string, string) {
	t.Helper()
	root := t.TempDir()
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	service := New(store)
	mount, err := service.SaveMount(context.Background(), entities.Mount{Name: "test", LocalPath: root, Mode: mode, Published: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return service, mount.ID, root
}

func TestRejectsTraversal(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	_, err := service.List(context.Background(), mountID, "../../", 100)
	if !errors.Is(err, ErrTraversal) {
		t.Fatalf("error = %v, want ErrTraversal", err)
	}
}

func TestRejectsSymlinkEscape(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	_, err := service.List(context.Background(), mountID, "escape", 100)
	if !errors.Is(err, ErrTraversal) {
		t.Fatalf("error = %v, want ErrTraversal", err)
	}
}

func TestUploadIsAtomicAndLeavesNoPartial(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	content := strings.Repeat("jolt", 1024)
	n, err := service.Upload(context.Background(), mountID, "nested.bin", strings.NewReader(content), false)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(content)) {
		t.Fatalf("written = %d", n)
	}
	got, err := os.ReadFile(filepath.Join(root, "nested.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatal("uploaded content differs")
	}
	matches, err := filepath.Glob(filepath.Join(root, ".jolt-*.partial"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("partial files remain: %v", matches)
	}
}

func TestReadOnlyBlocksWrites(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_only")
	_, err := service.Upload(context.Background(), mountID, "blocked.txt", strings.NewReader("no"), false)
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("error = %v, want ErrReadOnly", err)
	}
}

func TestDirectoryCopyPreservesStructure(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	if err := os.MkdirAll(filepath.Join(root, "source", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source", "deep", "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := service.Copy(context.Background(), mountID, "source", "copy", false)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("copied bytes = %d, want 4", n)
	}
	got, err := os.ReadFile(filepath.Join(root, "copy", "deep", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("content = %q", got)
	}
}

func TestDirectoryCannotBeCopiedIntoItself(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	if err := os.MkdirAll(filepath.Join(root, "source"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := service.Copy(context.Background(), mountID, "source", "source/copy", false)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}

func TestMoveMovesFileAndPreservesContents(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	if err := os.Mkdir(filepath.Join(root, "destination"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("important"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := service.Move(context.Background(), mountID, "source.txt", "destination/renamed.txt", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "source.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "destination", "renamed.txt"))
	if err != nil || string(content) != "important" {
		t.Fatalf("destination content=%q err=%v", content, err)
	}
}

func TestMoveRejectsUnsafeDestinationsWithoutChangingSource(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	if err := os.Mkdir(filepath.Join(root, "source"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source", "file.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"source", "source/nested"} {
		if _, err := os.Stat(filepath.Join(root, "source", "nested")); errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(filepath.Join(root, "source", "nested"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		err := service.Move(context.Background(), mountID, "source", destination, true)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("destination %q error=%v, want ErrInvalid", destination, err)
		}
		if _, err := os.Stat(filepath.Join(root, "source", "file.txt")); err != nil {
			t.Fatalf("source changed after rejected destination %q: %v", destination, err)
		}
	}
}

func TestMoveConflictAndOverwriteAreSafe(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "destination.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.Move(context.Background(), mountID, "source.txt", "destination.txt", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("error=%v, want ErrConflict", err)
	}
	for path, expected := range map[string]string{"source.txt": "new", "destination.txt": "old"} {
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(content) != expected {
			t.Fatalf("%s content=%q err=%v", path, content, err)
		}
	}
	if err := service.Move(context.Background(), mountID, "source.txt", "destination.txt", true); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, "destination.txt"))
	if err != nil || string(content) != "new" {
		t.Fatalf("overwritten content=%q err=%v", content, err)
	}
	if _, err := os.Stat(filepath.Join(root, "source.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source remained after overwrite: %v", err)
	}
}

func TestMoveReadOnlyIsBlocked(t *testing.T) {
	service, mountID, root := newTestService(t, "read_only")
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.Move(context.Background(), mountID, "source.txt", "destination.txt", false); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("error=%v, want ErrReadOnly", err)
	}
}

func TestMoveAllowsOverwriteWhenDestinationDoesNotExist(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := service.Move(context.Background(), mountID, "source.txt", "new.txt", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "new.txt")); err != nil {
		t.Fatalf("destination not moved: %v", err)
	}
}

func TestMoveRejectsMountRoot(t *testing.T) {
	service, mountID, _ := newTestService(t, "read_write")
	if err := service.Move(context.Background(), mountID, ".", "new-name", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error=%v, want ErrInvalid", err)
	}
}

func TestVerifiedCopyDoesNotPublishBeforeChecksumValidation(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "destination.txt"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := service.CopyFileVerified(context.Background(), mountID, "source.txt",
		"destination.txt", true, strings.Repeat("0", 64), false, nil)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("error = %v, want ErrSourceChanged", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "destination.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old" {
		t.Fatalf("destination was published before validation: %q", content)
	}
}

func TestResumableCopyContinuesFromDurableChunk(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	content := []byte(strings.Repeat("0123456789abcdef", 32*1024))
	if err := os.WriteFile(filepath.Join(root, "source.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	stopAfterFirstChunk := errors.New("checkpoint persisted")
	var checkpoint int64
	written, _, err := service.CopyFileResumable(context.Background(), mountID,
		"source.bin", "destination.bin", "job_test-0", false, 0, 64<<10, "", false,
		func(completed, _ int64) error {
			checkpoint = completed
			return stopAfterFirstChunk
		})
	if !errors.Is(err, stopAfterFirstChunk) || written != 64<<10 || checkpoint != 64<<10 {
		t.Fatalf("written=%d checkpoint=%d err=%v", written, checkpoint, err)
	}
	if _, err := os.Stat(filepath.Join(root, "destination.bin")); !os.IsNotExist(err) {
		t.Fatalf("destination published before completion, err=%v", err)
	}
	entries, err := service.List(context.Background(), mountID, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name, ".partial") {
			t.Fatalf("internal partial exposed by API listing: %+v", entry)
		}
	}
	if _, err := service.Metadata(context.Background(), mountID, ".jolt-job_test-0.partial"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("internal partial metadata error=%v, want ErrNotFound", err)
	}
	firstResumedCheckpoint := int64(0)
	written, _, err = service.CopyFileResumable(context.Background(), mountID,
		"source.bin", "destination.bin", "job_test-0", false, checkpoint, 64<<10, "", false,
		func(completed, _ int64) error {
			if firstResumedCheckpoint == 0 {
				firstResumedCheckpoint = completed
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if firstResumedCheckpoint != checkpoint+(64<<10) {
		t.Fatalf("copy restarted instead of resuming: first checkpoint=%d", firstResumedCheckpoint)
	}
	if written != int64(len(content)) {
		t.Fatalf("written=%d want=%d", written, len(content))
	}
	copied, err := os.ReadFile(filepath.Join(root, "destination.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != string(content) {
		t.Fatal("resumed content differs")
	}
	if matches, _ := filepath.Glob(filepath.Join(root, ".jolt-job_test-0.partial")); len(matches) != 0 {
		t.Fatalf("partial remains after completion: %v", matches)
	}
}

func TestParallelResumableCopyAdvancesOnlyContiguousBatches(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	content := []byte(strings.Repeat("parallel-chunks-", 32*1024))
	if err := os.WriteFile(filepath.Join(root, "parallel-source.bin"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	probe := &parallelProbeLimiter{gate: make(chan struct{})}
	var checkpoints []int64
	written, _, err := service.CopyFileResumableParallel(context.Background(), mountID,
		"parallel-source.bin", "parallel-destination.bin", "parallel-job", false,
		0, 64<<10, 4, "", false, func(completed, _ int64) error {
			if completed > 0 && (len(checkpoints) == 0 || checkpoints[len(checkpoints)-1] != completed) {
				checkpoints = append(checkpoints, completed)
			}
			return nil
		}, probe)
	if err != nil {
		t.Fatal(err)
	}
	if probe.maximum < 3 {
		t.Fatalf("chunks did not execute concurrently: maximum=%d", probe.maximum)
	}
	if len(checkpoints) == 0 || checkpoints[0] != 4*(64<<10) {
		t.Fatalf("first durable checkpoint was not the complete parallel batch: %v", checkpoints)
	}
	if written != int64(len(content)) {
		t.Fatalf("written=%d want=%d", written, len(content))
	}
	copied, err := os.ReadFile(filepath.Join(root, "parallel-destination.bin"))
	if err != nil || string(copied) != string(content) {
		t.Fatalf("parallel destination mismatch: bytes=%d err=%v", len(copied), err)
	}
}

func TestResumableRemoteReceiveContinuesFromDurableChunk(t *testing.T) {
	service, mountID, root := newTestService(t, "read_write")
	content := []byte(strings.Repeat("remote-chunk-", 32*1024))
	chunkSize := int64(64 << 10)
	stopAfterFirstChunk := errors.New("checkpoint persisted")
	var checkpoint int64
	written, _, err := service.ReceiveFileResumable(context.Background(), mountID,
		"received.bin", "job_remote", false, 0, chunkSize, int64(len(content)), "",
		strings.NewReader(string(content)), func(completed, _ int64) error {
			checkpoint = completed
			return stopAfterFirstChunk
		}, nil)
	if !errors.Is(err, stopAfterFirstChunk) || written != chunkSize || checkpoint != chunkSize {
		t.Fatalf("written=%d checkpoint=%d err=%v", written, checkpoint, err)
	}
	if _, err := os.Stat(filepath.Join(root, "received.bin")); !os.IsNotExist(err) {
		t.Fatalf("remote destination published before completion, err=%v", err)
	}
	written, _, err = service.ReceiveFileResumable(context.Background(), mountID,
		"received.bin", "job_remote", false, checkpoint, chunkSize, int64(len(content)), "",
		strings.NewReader(string(content[checkpoint:])), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(len(content)) {
		t.Fatalf("written=%d want=%d", written, len(content))
	}
	received, err := os.ReadFile(filepath.Join(root, "received.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(received) != string(content) {
		t.Fatal("resumed remote content differs")
	}
}

func TestProtectedInternalDirectoryCannotBecomeMount(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	service := New(store, keys)
	_, err = service.SaveMount(context.Background(), entities.Mount{Name: "keys", LocalPath: keys, Mode: "read_only"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
}
