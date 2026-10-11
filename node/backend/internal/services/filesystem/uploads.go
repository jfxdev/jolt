package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrOffsetMismatch reports that the client tried to append at an offset other
// than the one the partial file is actually at. Appending anywhere else would
// leave a hole or overwrite verified bytes, so the client is told the real
// offset and is expected to seek there and retry.
var ErrOffsetMismatch = errors.New("upload offset does not match the stored partial")

// UploadOffset returns how many bytes of a resumable upload already landed. A
// missing partial file is reported as offset zero rather than an error: that is
// exactly the state of a session whose first chunk never arrived.
func (s *Service) UploadOffset(ctx context.Context, mountID, destination, uploadID string) (int64, error) {
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(resumablePartialPath(dst, uploadID))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return info.Size(), nil
}

// AppendUpload writes one chunk at offset and returns the new offset. Each
// chunk is fsynced before the offset is reported, so a client that reads the
// offset back after a crash is told about bytes that are genuinely durable.
func (s *Service) AppendUpload(ctx context.Context, mountID, destination, uploadID string,
	offset, expectedSize int64, input io.Reader, limiters ...ByteRateLimiter) (int64, error) {
	mount, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, err
	}
	if err := writable(mount); err != nil {
		return 0, err
	}
	if offset < 0 || offset > expectedSize {
		return 0, fmt.Errorf("%w: offset is outside the declared size", ErrInvalid)
	}
	partialPath := resumablePartialPath(dst, uploadID)
	partial, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, err
	}
	defer partial.Close()
	info, err := partial.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() != offset {
		return info.Size(), fmt.Errorf("%w: stored %d, received %d", ErrOffsetMismatch, info.Size(), offset)
	}
	if _, err := partial.Seek(offset, io.SeekStart); err != nil {
		return offset, err
	}
	var source io.Reader = &contextReader{ctx: ctx, reader: input}
	if len(limiters) > 0 && limiters[0] != nil {
		source = &limitedReader{ctx: ctx, reader: source, limiter: limiters[0]}
	}
	// LimitReader caps the chunk at the declared total so a client cannot grow
	// the file past the size the session was authorized for.
	written, copyErr := io.Copy(partial, io.LimitReader(source, expectedSize-offset))
	completed := offset + written
	if syncErr := partial.Sync(); syncErr != nil && copyErr == nil {
		copyErr = syncErr
	}
	if copyErr != nil {
		return completed, copyErr
	}
	if completed == expectedSize {
		// Anything still buffered means the client sent more than it declared.
		var trailing [1]byte
		if count, readErr := source.Read(trailing[:]); count != 0 ||
			(readErr != nil && !errors.Is(readErr, io.EOF)) {
			return completed, fmt.Errorf("%w: upload exceeded the declared size", ErrInvalid)
		}
	}
	return completed, nil
}

// CompleteUpload verifies the assembled partial and publishes it with an atomic
// rename. The size is always checked and the checksum is checked when the
// client declared one, so a truncated or corrupted upload can never replace a
// good file at the destination.
func (s *Service) CompleteUpload(ctx context.Context, mountID, destination, uploadID string,
	expectedSize int64, expectedChecksum string, overwrite bool) (int64, string, error) {
	mount, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, "", err
	}
	if err := writable(mount); err != nil {
		return 0, "", err
	}
	partialPath := resumablePartialPath(dst, uploadID)
	partial, err := os.Open(partialPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, "", ErrNotFound
		}
		return 0, "", err
	}
	defer partial.Close()
	info, err := partial.Stat()
	if err != nil {
		return 0, "", err
	}
	if info.Size() != expectedSize {
		return info.Size(), "", fmt.Errorf("%w: upload holds %d of %d bytes",
			ErrInvalid, info.Size(), expectedSize)
	}
	checksum := ""
	if expectedChecksum != "" {
		hash := sha256.New()
		if _, err := io.Copy(hash, &contextReader{ctx: ctx, reader: partial}); err != nil {
			return info.Size(), "", err
		}
		checksum = hex.EncodeToString(hash.Sum(nil))
		if checksum != expectedChecksum {
			return info.Size(), checksum, fmt.Errorf("%w: upload checksum mismatch", ErrInvalid)
		}
	}
	if err := partial.Close(); err != nil {
		return info.Size(), checksum, err
	}
	// The conflict check is repeated here because the destination may have
	// appeared while the upload was in flight.
	if existing, statErr := os.Lstat(dst); statErr == nil {
		if existing.IsDir() {
			return info.Size(), checksum, ErrConflict
		}
		if !overwrite {
			return info.Size(), checksum, ErrConflict
		}
	}
	if err := os.Rename(partialPath, dst); err != nil {
		return info.Size(), checksum, err
	}
	return info.Size(), checksum, nil
}

// AbortUpload removes the partial file for a session. A missing partial is not
// an error: aborting an upload that never sent a byte must still succeed.
func (s *Service) AbortUpload(ctx context.Context, mountID, destination, uploadID string) error {
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// The destination's parent is gone, so the partial is gone with it.
			return nil
		}
		return err
	}
	if err := os.Remove(resumablePartialPath(dst, uploadID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
