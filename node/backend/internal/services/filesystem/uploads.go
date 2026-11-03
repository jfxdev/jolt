package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// Filesystem writers use a separate scope from the HTTP/state lifecycle lock.
// Both retain queued waiters until the last owner releases the gate.
func lockUpload(ctx context.Context, uploadID string) (func(), error) {
	return LockUploadSession(ctx, "file:"+uploadID)
}

// ErrOffsetMismatch reports that the client tried to append at an offset other
// than the one the partial file is actually at. Appending anywhere else would
// leave a hole or overwrite verified bytes, so the client is told the real
// offset and is expected to seek there and retry.
var ErrOffsetMismatch = errors.New("upload offset does not match the stored partial")

// ValidateUploadDestinationFiltered checks the persisted session destination
// before admission or resumption. The caller must load the session from state.
func (s *Service) ValidateUploadDestinationFiltered(ctx context.Context, session entities.UploadSession, filter *AccessFilter) error {
	if filter == nil || filter.context == nil || session.ID == "" || cleanRelative(session.Destination) == "." {
		return ErrInvalid
	}
	mount, destination, err := s.resolve(ctx, session.MountID, session.Destination, true)
	if err != nil {
		return err
	}
	if err := writable(mount); err != nil {
		return err
	}
	return validateFilteredFileDestination(ctx, mount, destination, session.Overwrite, filter)
}

// ValidateUploadCleanupFiltered authorizes removing only the session's partial,
// without requiring the destination to be absent or overwritable.
func (s *Service) ValidateUploadCleanupFiltered(ctx context.Context, session entities.UploadSession, filter *AccessFilter) error {
	if filter == nil || filter.context == nil || session.ID == "" || cleanRelative(session.Destination) == "." {
		return ErrInvalid
	}
	mount, destination, err := s.resolve(ctx, session.MountID, session.Destination, true)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(mount.LocalPath, destination)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrInvalid
	}
	relative = filepath.ToSlash(relative)
	if err := filter.checkAncestors(relative); err != nil {
		return err
	}
	if !filter.context.Evaluate(filter.base+"/"+relative, "create", "file").Allowed {
		return ErrFilteredBlocked
	}
	return ctx.Err()
}

func (s *Service) ValidateUploadReauthorizationFiltered(ctx context.Context, session entities.UploadSession, filter *AccessFilter) error {
	if err := s.ValidateUploadCleanupFiltered(ctx, session, filter); err != nil {
		return err
	}
	if session.Overwrite && !filter.context.Evaluate(filter.base+"/"+filepath.ToSlash(session.Destination), "update", "file").Allowed {
		return ErrFilteredBlocked
	}
	return ctx.Err()
}

// AppendUploadFiltered checks the persisted target before accepting a chunk.
// It remains internal until the API supplies a verified authorization context.
func (s *Service) AppendUploadFiltered(ctx context.Context, session entities.UploadSession, offset int64, input io.Reader, filter *AccessFilter, limiters ...ByteRateLimiter) (int64, error) {
	if err := s.ValidateUploadDestinationFiltered(ctx, session, filter); err != nil {
		return offset, err
	}
	return s.AppendUpload(ctx, session.MountID, session.Destination, session.ID, offset, session.Size, input, limiters...)
}

// PrepareUploadFiltered checks the session destination before hashing the
// partial or creating the empty partial used by zero-length uploads.
func (s *Service) PrepareUploadFiltered(ctx context.Context, session entities.UploadSession, filter *AccessFilter) (string, error) {
	if err := s.ValidateUploadDestinationFiltered(ctx, session, filter); err != nil {
		return "", err
	}
	return s.PrepareUpload(ctx, session)
}

// UploadOffset returns how many bytes of a resumable upload already landed. A
// missing partial file is reported as offset zero rather than an error: that is
// exactly the state of a session whose first chunk never arrived.
func (s *Service) UploadOffset(ctx context.Context, mountID, destination, uploadID string) (int64, error) {
	if cleanRelative(destination) == "." {
		return 0, ErrInvalid
	}
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, err
	}
	info, err := safeStat(resumablePartialPath(dst, uploadID))
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
	if expectedSize > s.maxUploadBytes {
		return 0, ErrUploadTooLarge
	}
	if offset < 0 || offset > expectedSize {
		return 0, fmt.Errorf("%w: offset is outside the declared size", ErrInvalid)
	}
	unlock, err := lockUpload(ctx, uploadID)
	if err != nil {
		return 0, err
	}
	defer unlock()
	partialPath := resumablePartialPath(dst, uploadID)
	partial, err := safeOpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
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
	written, copyErr := io.Copy(&uploadWriter{service: s, file: partial, limit: expectedSize - offset}, io.LimitReader(source, expectedSize-offset))
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
	return s.completeUpload(ctx, mountID, destination, uploadID, expectedSize, expectedChecksum, overwrite, nil)
}

// CompleteUploadFiltered revalidates the persisted target before publishing.
// It is internal until all upload handlers carry a verified context.
func (s *Service) CompleteUploadFiltered(ctx context.Context, session entities.UploadSession, expectedChecksum string, filter *AccessFilter) (int64, string, error) {
	if filter == nil || filter.context == nil || session.ID == "" {
		return 0, "", ErrInvalid
	}
	return s.completeUpload(ctx, session.MountID, session.Destination, session.ID, session.Size, expectedChecksum, session.Overwrite, filter)
}

func (s *Service) completeUpload(ctx context.Context, mountID, destination, uploadID string,
	expectedSize int64, expectedChecksum string, overwrite bool, filter *AccessFilter) (int64, string, error) {
	mount, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, "", err
	}
	if err := writable(mount); err != nil {
		return 0, "", err
	}
	unlock, err := lockUpload(ctx, uploadID)
	if err != nil {
		return 0, "", err
	}
	defer unlock()
	if filter != nil {
		if err := validateFilteredFileDestination(ctx, mount, dst, overwrite, filter); err != nil {
			return 0, "", err
		}
	}
	partialPath := resumablePartialPath(dst, uploadID)
	// A zero-byte upload sends no chunk at all, so its partial file was never
	// created. Materializing it here lets an empty file publish through the
	// same verified path as any other instead of failing as "not found".
	if expectedSize == 0 {
		if _, statErr := safeStat(partialPath); errors.Is(statErr, os.ErrNotExist) {
			empty, createErr := safeOpenFile(partialPath, os.O_CREATE|os.O_WRONLY, 0o600)
			if createErr != nil {
				return 0, "", createErr
			}
			if closeErr := empty.Close(); closeErr != nil {
				return 0, "", closeErr
			}
		}
	}
	partial, err := safeOpen(partialPath)
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
	if err := s.inspectUpload(partial); err != nil {
		return info.Size(), checksum, err
	}
	if err := partial.Close(); err != nil {
		return info.Size(), checksum, err
	}
	// The conflict check is repeated here because the destination may have
	// appeared while the upload was in flight.
	if filter != nil {
		if err := validateFilteredFileDestination(ctx, mount, dst, overwrite, filter); err != nil {
			return info.Size(), checksum, err
		}
	} else if existing, statErr := safeLstat(dst); statErr == nil {
		if existing.IsDir() {
			return info.Size(), checksum, ErrConflict
		}
		if !overwrite {
			return info.Size(), checksum, ErrConflict
		}
	}
	if err := ctx.Err(); err != nil {
		return info.Size(), checksum, err
	}
	if err := publishPath(partialPath, dst, overwrite); err != nil {
		return info.Size(), checksum, err
	}
	return info.Size(), checksum, syncUploadDirectory(dst)
}

// AbortUpload removes the partial file for a session. A missing partial is not
// an error: aborting an upload that never sent a byte must still succeed.
func (s *Service) AbortUpload(ctx context.Context, mountID, destination, uploadID string) error {
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if errors.Is(err, ErrHiddenName) {
		// The operator may hide a destination while an upload is in progress.
		// Cleanup can unlink only its internal partial, never the destination.
		mount, mountErr := s.GetMount(ctx, mountID)
		if mountErr != nil {
			return mountErr
		}
		clean := cleanRelative(destination)
		if filepath.IsAbs(destination) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return ErrTraversal
		}
		dst, err = filepath.Join(mount.LocalPath, clean), nil
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// The destination's parent is gone, so the partial is gone with it.
			return nil
		}
		return err
	}
	unlock, err := lockUpload(ctx, uploadID)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := safeRemove(resumablePartialPath(dst, uploadID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
