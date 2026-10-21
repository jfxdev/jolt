package filesystem

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSafeWalkDirReadErrorVisitorResult(t *testing.T) {
	visitorError := errors.New("visitor failed")
	for _, tc := range []struct {
		name        string
		visitError  error
		wantError   error
		wantSibling bool
	}{
		{"skip directory", fs.SkipDir, nil, true},
		{"continue", nil, nil, true},
		{"preserve error", visitorError, visitorError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			unreadable := filepath.Join(root, "a-unreadable")
			sibling := filepath.Join(root, "b-sibling")
			for _, path := range []string{unreadable, sibling} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var sawReadError, sawSibling bool
			err = safeWalkDir(root, func(path string, entry fs.DirEntry, readErr error) error {
				if path == unreadable {
					if readErr != nil {
						sawReadError = true
						return tc.visitError
					}
					// Force ReadDir to fail after the initial visit, regardless of
					// process privileges or permission semantics on the host.
					return os.Remove(path)
				}
				if path == sibling {
					sawSibling = true
				}
				return readErr
			})
			if !errors.Is(err, tc.wantError) || !sawReadError || sawSibling != tc.wantSibling {
				t.Fatalf("error=%v readError=%v sibling=%v", err, sawReadError, sawSibling)
			}
		})
	}
}

type beforeRead struct {
	once   sync.Once
	before func()
	input  io.Reader
}

func (r *beforeRead) Read(b []byte) (int, error) { r.once.Do(r.before); return r.input.Read(b) }

func TestUploadNeverOverwritesAFileCreatedWhileReceiving(t *testing.T) {
	s, m, root := newTestService(t, "read_write")
	path := filepath.Join(root, "destination.txt")
	input := &beforeRead{input: strings.NewReader("new"), before: func() { writeFile(t, path, "external writer") }}
	if _, err := s.Upload(context.Background(), m, "destination.txt", input, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("error=%v", err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil || string(bytes) != "external writer" {
		t.Fatalf("destination=%q error=%v", bytes, err)
	}
}

func TestConcurrentUploadsPublishExactlyOneWinner(t *testing.T) {
	s, m, root := newTestService(t, "read_write")
	gate := make(chan struct{})
	results := make(chan error, 8)
	for range 8 {
		go func() {
			<-gate
			_, err := s.Upload(context.Background(), m, "winner.txt", strings.NewReader("complete-content"), false)
			results <- err
		}()
	}
	close(gate)
	wins := 0
	for range 8 {
		err := <-results
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatalf("unexpected error=%v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("winners=%d", wins)
	}
	bytes, err := os.ReadFile(filepath.Join(root, "winner.txt"))
	if err != nil || string(bytes) != "complete-content" {
		t.Fatalf("bytes=%q error=%v", bytes, err)
	}
}

func TestSymlinksCannotAliasAnotherAuthorizationScope(t *testing.T) {
	s, m, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "private", "secret.txt"), "secret")
	if err := os.MkdirAll(filepath.Join(root, "public"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ name, target string }{{"public/alias.txt", "../private/secret.txt"}, {"public/alias-dir", "../private"}} {
		if err := os.Symlink(link.target, filepath.Join(root, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, relative := range []string{"public/alias.txt", "public/alias-dir/secret.txt"} {
		file, _, err := s.Open(context.Background(), m, relative)
		if file != nil {
			file.Close()
		}
		if !errors.Is(err, ErrTraversal) {
			t.Fatalf("path=%s error=%v", relative, err)
		}
	}
	if _, err := s.Upload(context.Background(), m, "public/alias-dir/new.txt", strings.NewReader("bad"), false); !errors.Is(err, ErrTraversal) {
		t.Fatalf("write error=%v", err)
	}
	if err := s.Delete(context.Background(), m, "public/alias.txt", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "private", "secret.txt")); err != nil {
		t.Fatalf("deleting link removed target: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "public", "alias.txt")); !os.IsNotExist(err) {
		t.Fatalf("link still exists: %v", err)
	}
	if err := s.Move(context.Background(), m, "public/alias-dir", "public/moved-link", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "private", "secret.txt")); err != nil {
		t.Fatalf("moving link changed target: %v", err)
	}
}

func TestParentSymlinkSwapDuringUploadCannotPublishOutsideMount(t *testing.T) {
	s, m, root := newTestService(t, "read_write")
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "destination"), 0700); err != nil {
		t.Fatal(err)
	}
	input := &beforeRead{input: strings.NewReader("new"), before: func() {
		if err := os.Rename(filepath.Join(root, "destination"), filepath.Join(root, "original")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "destination")); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := s.Upload(context.Background(), m, "destination/file.txt", input, false); !errors.Is(err, ErrTraversal) {
		t.Fatalf("error=%v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside entries=%v error=%v", entries, err)
	}
}

func TestNoReplaceMovePreservesExistingDirectory(t *testing.T) {
	s, m, root := newTestService(t, "read_write")
	writeFile(t, filepath.Join(root, "source", "a.txt"), "source")
	writeFile(t, filepath.Join(root, "destination", "b.txt"), "destination")
	if err := s.Move(context.Background(), m, "source", "destination", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("error=%v", err)
	}
	for _, relative := range []string{"source/a.txt", "destination/b.txt"} {
		if _, err := os.Stat(filepath.Join(root, relative)); err != nil {
			t.Fatal(err)
		}
	}
}
