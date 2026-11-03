package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

type cancelAfterMountRead struct {
	serviceStore
	remaining int
	cancel    context.CancelFunc
}

type cancelOnCheck struct {
	context.Context
	checks int
	cancel context.CancelFunc
}

func (c *cancelOnCheck) Err() error {
	c.checks--
	if c.checks == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func (s *cancelAfterMountRead) GetMount(ctx context.Context, id string) (entities.Mount, error) {
	mount, err := s.serviceStore.GetMount(ctx, id)
	s.remaining--
	if s.remaining == 0 {
		s.cancel()
	}
	return mount, err
}

func TestDestructiveOperationsStopWhenCanceledAfterMountLookup(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mountReads int
		operation  func(context.Context, *Service, string) error
	}{
		{"delete", 1, func(ctx context.Context, s *Service, mount string) error {
			return s.Delete(ctx, mount, "source", false)
		}},
		{"move", 2, func(ctx context.Context, s *Service, mount string) error {
			return s.Move(ctx, mount, "source", "destination", true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, mount, root := newTestService(t, "read_write")
			writeFile(t, filepath.Join(root, "source"), "source")
			writeFile(t, filepath.Join(root, "destination"), "destination")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.store = &cancelAfterMountRead{serviceStore: s.store, remaining: tc.mountReads, cancel: cancel}
			if err := tc.operation(ctx, s, mount); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			for name, contents := range map[string]string{"source": "source", "destination": "destination"} {
				got, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(got) != contents {
					t.Fatalf("%s changed: %q %v", name, got, err)
				}
			}
		})
	}
}

func TestTreeMutationsRejectNestedSymlinkBeforeChanges(t *testing.T) {
	for _, operation := range []string{"delete", "move", "overwrite"} {
		t.Run(operation, func(t *testing.T) {
			s, mount, root := newTestService(t, "read_write")
			tree := filepath.Join(root, "tree")
			writeFile(t, filepath.Join(tree, "visible.txt"), "keep")
			if err := os.Symlink("visible.txt", filepath.Join(tree, "link")); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "source.txt"), "source")
			var err error
			switch operation {
			case "delete":
				err = s.Delete(context.Background(), mount, "tree", true)
			case "move":
				err = s.Move(context.Background(), mount, "tree", "new-tree", false)
			case "overwrite":
				err = s.Move(context.Background(), mount, "source.txt", "tree", true)
			}
			if !errors.Is(err, ErrProtectedTree) {
				t.Fatalf("got %v", err)
			}
			for _, name := range []string{"tree/visible.txt", "tree/link", "source.txt"} {
				if _, err := os.Lstat(filepath.Join(root, name)); err != nil {
					t.Fatalf("%s changed: %v", name, err)
				}
			}
		})
	}
}

func TestRecursiveRemovalReportsCancellationAfterPartialWork(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three"} {
		writeFile(t, filepath.Join(root, name), name)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	visited := 0
	err = safeRemoveProtected(ctx, root, func(string) bool {
		visited++
		if visited == 2 {
			cancel()
		}
		return false
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 2 {
		t.Fatalf("expected one removal and two retained entries, got %d: %v", len(entries), err)
	}
}

func TestMoveRestoresDestinationWhenCanceledAfterBackup(t *testing.T) {
	s, mount, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source"), "source")
	writeFile(t, filepath.Join(root, "destination"), "destination")
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Two mount lookups, the pre-mutation check, then the backup check.
	ctx := &cancelOnCheck{Context: base, checks: 4, cancel: cancel}
	if err := s.Move(ctx, mount, "source", "destination", true); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation after backup, got %v", err)
	}
	for name, contents := range map[string]string{"source": "source", "destination": "destination"} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != contents {
			t.Fatalf("%s changed: %q %v", name, got, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 2 {
		t.Fatalf("unexpected backup remains: %v %v", entries, err)
	}
}

func TestRecursiveRemovalReportsExternalDisappearance(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "file"), "data")
	err = safeRemoveProtected(context.Background(), root, func(name string) bool {
		if removeErr := os.Remove(filepath.Join(root, name)); removeErr != nil {
			t.Fatal(removeErr)
		}
		return false
	})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("external disappearance should fail, got %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("root unexpectedly removed: %v", err)
	}
}

func TestRecursiveRemovalRejectsProtectedEntryCreatedAfterPreflight(t *testing.T) {
	s, mountID, _ := newTestService(t, "read_write")
	mount, err := s.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	mount.HiddenPatterns = []string{"*.pem"}
	tree := filepath.Join(mount.LocalPath, "tree")
	writeFile(t, filepath.Join(tree, "visible"), "data")
	if err := rejectProtectedTree(context.Background(), mount, tree); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tree, "new.PEM"), "protected")
	err = safeRemoveProtected(context.Background(), tree, func(name string) bool { return hiddenName(mount, name) })
	if !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("expected protected-tree error, got %v", err)
	}
	got, err := os.ReadFile(filepath.Join(tree, "new.PEM"))
	if err != nil || string(got) != "protected" {
		t.Fatalf("new protected entry changed: %q %v", got, err)
	}
}
