package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUploadLimitsRejectUnknownLengthStreamsAndOversizedSessions(t *testing.T) {
	s, m, root := newTestService(t, "read_write")
	s.ConfigureUploadLimits(4, 0)
	if _, err := s.Upload(context.Background(), m, "stream.bin", strings.NewReader("12345"), false); !errors.Is(err, ErrUploadTooLarge) {
		t.Fatalf("stream error=%v", err)
	}
	if _, err := s.AppendUpload(context.Background(), m, "chunk.bin", "upl_limit", 0, 5, strings.NewReader("12345")); !errors.Is(err, ErrUploadTooLarge) {
		t.Fatalf("chunk error=%v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected upload left files: %v %v", entries, err)
	}
}

func TestUploadStopsBeforeUsingTheDiskSafetyMargin(t *testing.T) {
	s, m, root := newTestService(t, "read_write")
	s.ConfigureUploadLimits(100, 10)
	s.spaceAvailable = func(*os.File) (int64, error) { return 12, nil }
	if _, err := s.Upload(context.Background(), m, "full.bin", strings.NewReader("1234"), false); !errors.Is(err, ErrInsufficientSpace) {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "full.bin")); !os.IsNotExist(err) {
		t.Fatalf("destination published: %v", err)
	}
	s.spaceAvailable = func(*os.File) (int64, error) { return 0, unix.ENOSPC }
	if _, err := s.Upload(context.Background(), m, "failed.bin", strings.NewReader("1234"), false); err == nil {
		t.Fatal("ENOSPC ignored")
	}
}

func TestUploadCannotUseTheMountRootAsAFile(t *testing.T) {
	s, m, _ := newTestService(t, "read_write")
	for _, path := range []string{"", ".", "sub/.."} {
		if _, err := s.Upload(context.Background(), m, path, strings.NewReader("x"), false); !errors.Is(err, ErrInvalid) {
			t.Fatalf("path=%q error=%v", path, err)
		}
	}
}
