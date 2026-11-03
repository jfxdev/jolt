package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDestructiveTreeSnapshotTracksChanges(t *testing.T) {
	s, mountID, root := newTestService(t, "read_write")
	dir := filepath.Join(root, "tree")
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "nested", "file.txt")
	if err := os.WriteFile(file, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := s.SnapshotDestructiveTree(context.Background(), mountID, "tree")
	if err != nil || first.Version != 1 || first.Files != 1 || first.Directories != 2 || first.Bytes != 3 || len(first.Digest) != 64 {
		t.Fatalf("first snapshot=%+v err=%v", first, err)
	}
	again, err := s.SnapshotDestructiveTree(context.Background(), mountID, "tree")
	if err != nil || again != first {
		t.Fatalf("snapshot not stable: %+v %v", again, err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, file); err != nil {
		t.Fatal(err)
	}
	changed, err := s.SnapshotDestructiveTree(context.Background(), mountID, "tree")
	if err != nil || changed.Digest == first.Digest || changed.Files != first.Files || changed.Bytes != first.Bytes {
		t.Fatalf("replacement not detected: %+v %v", changed, err)
	}
	info, err = os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("six"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	edited, err := s.SnapshotDestructiveTree(context.Background(), mountID, "tree")
	if err != nil || edited.Digest == changed.Digest || edited.Bytes != changed.Bytes {
		t.Fatalf("same-size edit with restored mtime not detected: %+v %v", edited, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	added, err := s.SnapshotDestructiveTree(context.Background(), mountID, "tree")
	if err != nil || added.Digest == edited.Digest || added.Files != 2 || added.Bytes != 8 {
		t.Fatalf("addition not detected: %+v %v", added, err)
	}
}

func TestDestructiveTreeSnapshotFailsClosed(t *testing.T) {
	s, mountID, root := newTestService(t, "read_write")
	dir := filepath.Join(root, "tree")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	mount, err := s.GetMount(context.Background(), mountID)
	if err != nil {
		t.Fatal(err)
	}
	mount.HiddenPatterns = []string{"*.secret"}
	if _, err := s.SaveMount(context.Background(), mount); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "private.secret")
	if err := os.WriteFile(secret, []byte("do not expose"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SnapshotDestructiveTree(context.Background(), mountID, "tree"); !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("hidden tree: %v", err)
	}
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SnapshotDestructiveTree(context.Background(), mountID, "tree"); !errors.Is(err, ErrProtectedTree) {
		t.Fatalf("symlink tree: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.SnapshotDestructiveTree(ctx, mountID, "tree"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	for _, target := range []string{".", "../outside", "a/../tree", "tree/", " tree", `/tree`, `tree\child`} {
		if _, err := s.SnapshotDestructiveTree(context.Background(), mountID, target); err == nil {
			t.Fatalf("invalid path %q accepted", target)
		}
	}
	readOnly, readOnlyID, readOnlyRoot := newTestService(t, "read_only")
	if err := os.Mkdir(filepath.Join(readOnlyRoot, "tree"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readOnly.SnapshotDestructiveTree(context.Background(), readOnlyID, "tree"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only mount: %v", err)
	}
}
