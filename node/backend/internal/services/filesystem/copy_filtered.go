package filesystem

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// InspectCopyDestinationFiltered checks destination permissions without
// creating paths, including paths whose parent is planned but not present yet.
// Existing files require both create and update; this is intentionally
// conservative until final conflict decisions are enforced at runtime.
func (s *Service) InspectCopyDestinationFiltered(ctx context.Context, mountID, relative, kind string, filter *AccessFilter) (entities.FileEntry, bool, error) {
	if filter == nil || filter.context == nil || (kind != "file" && kind != "directory") || relative == "" || relative == "." || path.IsAbs(relative) || path.Clean(relative) != relative || strings.ContainsAny(relative, "\\\x00") {
		return entities.FileEntry{}, false, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return entities.FileEntry{}, false, err
	}
	// GetMount probes the live mount; the persisted record of a mount defined in
	// node.yaml does not carry the writable flag.
	mount, err := s.GetMount(ctx, mountID)
	if err != nil {
		return entities.FileEntry{}, false, err
	}
	if !mount.Enabled {
		return entities.FileEntry{}, false, ErrDisabled
	}
	if err := writable(mount); err != nil {
		return entities.FileEntry{}, false, err
	}
	for _, component := range strings.Split(relative, "/") {
		if component == "" || component == "." || component == ".." || hiddenName(mount, component) {
			return entities.FileEntry{}, false, ErrHiddenName
		}
	}
	destination := filepath.Join(mount.LocalPath, filepath.FromSlash(relative))
	if !within(mount.LocalPath, destination) {
		return entities.FileEntry{}, false, ErrTraversal
	}
	if kind == "file" {
		// A directory already at the destination is reported as a conflict;
		// the file validator below would refuse it as a protected tree.
		if info, err := safeLstat(destination); err == nil && info.IsDir() {
			if err := filter.checkAncestors(relative); err != nil {
				return entities.FileEntry{}, false, err
			}
			if !filter.context.Evaluate(filter.base+"/"+relative, "create", "file").Allowed {
				return entities.FileEntry{}, false, ErrFilteredBlocked
			}
			return entities.FileEntry{Name: info.Name(), Path: relative, Type: "directory", Size: info.Size(), ModifiedAt: info.ModTime().UTC()}, true, nil
		}
		if err := validateFilteredFileDestination(ctx, mount, destination, true, filter); err != nil {
			return entities.FileEntry{}, false, err
		}
	} else {
		if err := filter.checkAncestors(relative); err != nil {
			return entities.FileEntry{}, false, err
		}
		if !filter.context.Evaluate(filter.base+"/"+relative, "create", "directory").Allowed {
			return entities.FileEntry{}, false, ErrFilteredBlocked
		}
	}
	info, err := safeLstat(destination)
	if errors.Is(err, fs.ErrNotExist) {
		if err := ctx.Err(); err != nil {
			return entities.FileEntry{}, false, err
		}
		return entities.FileEntry{}, false, nil
	}
	if err != nil {
		return entities.FileEntry{}, false, err
	}
	// A regular file where a directory is planned (or the reverse) is a plain
	// conflict for the caller to report. Links and special files stay refused.
	if !info.Mode().IsRegular() && !info.IsDir() {
		return entities.FileEntry{}, false, ErrProtectedTree
	}
	if kind == "file" && !info.Mode().IsRegular() || kind == "directory" && !info.IsDir() {
		actual := "file"
		if info.IsDir() {
			actual = "directory"
		}
		return entities.FileEntry{Name: info.Name(), Path: relative, Type: actual, Size: info.Size(), ModifiedAt: info.ModTime().UTC()}, true, nil
	}
	if kind == "file" {
		if err := validateFilteredFileDestination(ctx, mount, destination, true, filter); err != nil {
			return entities.FileEntry{}, false, err
		}
	}
	if kind == "directory" {
		if err := filter.checkRoot(relative, info); err != nil {
			return entities.FileEntry{}, false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return entities.FileEntry{}, false, err
	}
	return entities.FileEntry{Name: info.Name(), Path: relative, Type: kind, Size: info.Size(), ModifiedAt: info.ModTime().UTC()}, true, nil
}

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
