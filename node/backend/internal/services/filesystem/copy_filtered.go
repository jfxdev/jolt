package filesystem

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

func (s *Service) validateResumableCopyPublication(ctx context.Context, mountID, source string, mount entities.Mount, destination string, overwrite bool, original os.FileInfo, filter *AccessFilter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if filter == nil {
		return nil
	}
	current, info, err := s.OpenFiltered(ctx, mountID, source, filter)
	if err != nil {
		return err
	}
	closeErr := current.Close()
	if closeErr != nil {
		return closeErr
	}
	if !os.SameFile(original, info) {
		return ErrSourceChanged
	}
	return validateFilteredFileDestination(ctx, mount, destination, overwrite, filter)
}

// CopyTreeFiltered copies authorized entries only. It is internal until the
// same context is carried and enforced across every file operation.
func (s *Service) CopyTreeFiltered(ctx context.Context, mountID, source, destination string, overwrite bool, filter *AccessFilter) (int64, error) {
	if filter == nil || filter.context == nil || cleanRelative(source) == cleanRelative(destination) {
		return 0, ErrInvalid
	}
	mount, src, err := s.resolve(ctx, mountID, source, false)
	if err != nil {
		return 0, err
	}
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, err
	}
	if err := writable(mount); err != nil {
		return 0, err
	}
	info, err := safeStat(src)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() || within(src, dst) {
		return 0, ErrInvalid
	}
	if err := filter.checkRoot(cleanRelativeSlash(source), info); err != nil {
		return 0, err
	}
	var written int64
	err = safeWalkDirStreaming(src, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if current != src && hiddenName(mount, entry.Name()) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := safeLstat(current)
		if err != nil {
			return err
		}
		// A concurrent type change must not cause a directory to bypass traversal checks.
		if entry.IsDir() != info.IsDir() {
			return ErrInvalid
		}
		sourcePath, err := filepath.Rel(mount.LocalPath, current)
		if err != nil {
			return err
		}
		if err := filter.checkRoot(filepath.ToSlash(sourcePath), info); err != nil {
			if current == src {
				return err
			}
			if errors.Is(err, ErrFilteredHidden) || errors.Is(err, ErrFilteredBlocked) {
				if info.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return err
		}
		part, err := filepath.Rel(src, current)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, part)
		if info.IsDir() {
			err := ensureFilteredCopyDirectory(ctx, mount, target, overwrite, filter)
			if current != src && (errors.Is(err, ErrFilteredHidden) || errors.Is(err, ErrFilteredBlocked)) {
				return fs.SkipDir
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		check := func() error { return validateFilteredFileDestination(ctx, mount, target, overwrite, filter) }
		if err := check(); err != nil {
			if errors.Is(err, ErrFilteredHidden) || errors.Is(err, ErrFilteredBlocked) {
				return nil
			}
			return err
		}
		file, err := safeOpen(current)
		if err != nil {
			return err
		}
		opened, err := file.Stat()
		if err == nil && (!opened.Mode().IsRegular() || filter.checkRoot(filepath.ToSlash(sourcePath), opened) != nil) {
			err = ErrFilteredHidden
		}
		if err != nil {
			file.Close()
			return err
		}
		n, err := copyAtomicWithCheck(ctx, mount, file, target, overwrite, opened.Size(), 0, nil, check)
		closeErr := file.Close()
		written += n
		if err != nil {
			return err
		}
		return closeErr
	})
	return written, err
}

// Existing directories are merged, never removed. mkdir operates on one level,
// so a denied or missing parent cannot be created implicitly.
func ensureFilteredCopyDirectory(ctx context.Context, mount entities.Mount, target string, overwrite bool, filter *AccessFilter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	relative, err := filepath.Rel(mount.LocalPath, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrInvalid
	}
	relative = filepath.ToSlash(relative)
	if err := filter.checkAncestors(relative); err != nil {
		return err
	}
	if !filter.context.Evaluate(filter.base+"/"+relative, "create", "directory").Allowed {
		return ErrFilteredBlocked
	}
	info, err := safeLstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return safeMkdir(target, 0o777)
	}
	if err != nil {
		return err
	}
	if !overwrite {
		return ErrConflict
	}
	if !info.IsDir() {
		return ErrProtectedTree
	}
	return filter.checkRoot(relative, info)
}
