package filesystem

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var (
	ErrUploadTooLarge    = errors.New("upload exceeds the configured size limit")
	ErrInsufficientSpace = errors.New("insufficient free space for upload")
)

const DefaultMaxUploadBytes int64 = 100 << 30
const DefaultUploadMinFreeBytes int64 = 1 << 30

func (s *Service) ConfigureUploadLimits(maxBytes, minFreeBytes int64) {
	if maxBytes > 0 {
		s.maxUploadBytes = maxBytes
	}
	if minFreeBytes >= 0 {
		s.uploadMinFreeBytes = minFreeBytes
	}
}

func freeBytes(file *os.File) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &st); err != nil {
		return 0, err
	}
	bytes := uint64(st.Bavail) * uint64(st.Bsize)
	if bytes > uint64(1<<63-1) {
		return 1<<63 - 1, nil
	}
	return int64(bytes), nil
}

// Admission is conservative: reserve the unwritten bytes of other sessions
// before accepting another declaration, then check again on every write.
func (s *Service) CheckUploadCapacity(ctx context.Context, mountID, destination string, required int64) error {
	if cleanRelative(destination) == "." {
		return ErrInvalid
	}
	if required < 0 {
		return ErrInvalid
	}
	mount, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return err
	}
	if err := writable(mount); err != nil {
		return err
	}
	parent, err := safeOpen(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer parent.Close()
	available, err := s.spaceAvailable(parent)
	if err != nil {
		return err
	}
	if available < s.uploadMinFreeBytes || required > available-s.uploadMinFreeBytes {
		return ErrInsufficientSpace
	}
	return nil
}

type uploadWriter struct {
	service        *Service
	file           *os.File
	written, limit int64
}

func (w *uploadWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.limit-w.written {
		return 0, fmt.Errorf("%w: máximo %d bytes", ErrUploadTooLarge, w.limit)
	}
	w.service.uploadWriteMu.Lock()
	defer w.service.uploadWriteMu.Unlock()
	available, err := w.service.spaceAvailable(w.file)
	if err != nil {
		return 0, err
	}
	if available < w.service.uploadMinFreeBytes || int64(len(data)) > available-w.service.uploadMinFreeBytes {
		return 0, ErrInsufficientSpace
	}
	n, err := w.file.Write(data)
	w.written += int64(n)
	if errors.Is(err, unix.ENOSPC) {
		err = ErrInsufficientSpace
	}
	return n, err
}
