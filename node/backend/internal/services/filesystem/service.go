package filesystem

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfxdev/jolt/backend/internal/contracts"
	"github.com/jfxdev/jolt/backend/internal/entities"
	"github.com/jfxdev/jolt/backend/internal/infra/db"
)

var (
	ErrNotFound      = errors.New("resource not found")
	ErrReadOnly      = errors.New("mount is read-only")
	ErrTraversal     = errors.New("path escapes mount")
	ErrConflict      = errors.New("destination already exists")
	ErrDisabled      = errors.New("mount is disabled")
	ErrInvalid       = errors.New("invalid request")
	ErrSourceChanged = errors.New("source changed during copy")
)

type Service struct {
	store          contracts.Store
	now            func() time.Time
	forbiddenRoots []string
}

type ByteRateLimiter interface {
	Wait(context.Context, int64) error
}

type limitedReader struct {
	ctx     context.Context
	reader  io.Reader
	limiter ByteRateLimiter
}

func (r *limitedReader) Read(buffer []byte) (int, error) {
	count, err := r.reader.Read(buffer)
	if count > 0 && r.limiter != nil {
		if waitErr := r.limiter.Wait(r.ctx, int64(count)); waitErr != nil {
			return 0, waitErr
		}
	}
	return count, err
}

func New(store contracts.Store, forbiddenRoots ...string) *Service {
	cleaned := make([]string, 0, len(forbiddenRoots))
	for _, root := range forbiddenRoots {
		if root == "" {
			continue
		}
		if absolute, err := filepath.Abs(root); err == nil {
			if evaluated, evalErr := filepath.EvalSymlinks(absolute); evalErr == nil {
				absolute = evaluated
			}
			cleaned = append(cleaned, filepath.Clean(absolute))
		}
	}
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }, forbiddenRoots: cleaned}
}

func (s *Service) ListMounts(ctx context.Context) ([]entities.Mount, error) {
	mounts, err := s.store.ListMounts(ctx)
	if err != nil {
		return nil, err
	}
	for i := range mounts {
		diagnose(&mounts[i])
	}
	return mounts, nil
}

func (s *Service) GetMount(ctx context.Context, id string) (entities.Mount, error) {
	m, err := s.store.GetMount(ctx, id)
	if errors.Is(err, db.ErrNotFound) {
		return m, ErrNotFound
	}
	if err == nil {
		diagnose(&m)
	}
	return m, err
}

func (s *Service) SaveMount(ctx context.Context, mount entities.Mount) (entities.Mount, error) {
	mount.Name = strings.TrimSpace(mount.Name)
	if mount.Name == "" {
		return mount, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	absolute, err := filepath.Abs(mount.LocalPath)
	if err != nil {
		return mount, fmt.Errorf("%w: invalid local path", ErrInvalid)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return mount, fmt.Errorf("%w: local path is unavailable: %v", ErrInvalid, err)
	}
	if !info.IsDir() {
		return mount, fmt.Errorf("%w: only directory mounts are supported", ErrInvalid)
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return mount, fmt.Errorf("%w: cannot resolve local path", ErrInvalid)
	}
	for _, forbidden := range s.forbiddenRoots {
		if within(absolute, forbidden) || within(forbidden, absolute) {
			return mount, fmt.Errorf("%w: mount overlaps a protected internal directory", ErrInvalid)
		}
	}
	if mount.Mode != "read_only" && mount.Mode != "read_write" {
		return mount, fmt.Errorf("%w: mode must be read_only or read_write", ErrInvalid)
	}
	mount.LocalPath = filepath.Clean(absolute)
	mount.TargetType = "directory"
	if mount.ID == "" {
		mount.ID = newID("mnt")
	}
	now := s.now()
	if mount.CreatedAt.IsZero() {
		mount.CreatedAt = now
	}
	mount.UpdatedAt = now
	diagnose(&mount)
	if err := s.store.UpsertMount(ctx, mount); err != nil {
		return mount, err
	}
	return mount, nil
}

func (s *Service) DeleteMount(ctx context.Context, id string) error {
	if err := s.store.DeleteMount(ctx, id); errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	} else if errors.Is(err, db.ErrInUse) {
		return fmt.Errorf("%w: mount is referenced by an active transfer grant", ErrConflict)
	} else {
		return err
	}
}

func (s *Service) List(ctx context.Context, mountID, relative string, limit int) ([]entities.FileEntry, error) {
	mount, resolved, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return nil, err
	}
	if !mount.Enabled {
		return nil, ErrDisabled
	}
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return nil, err
	}
	visible := entries[:0]
	for _, entry := range entries {
		if !isInternalPartialName(entry.Name()) {
			visible = append(visible, entry)
		}
	}
	entries = visible
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return strings.ToLower(entries[i].Name()) < strings.ToLower(entries[j].Name())
	})
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]entities.FileEntry, 0, len(entries))
	base := cleanRelative(relative)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		kind := "file"
		if entry.IsDir() {
			kind = "directory"
		} else if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		out = append(out, entities.FileEntry{
			Name: entry.Name(), Path: filepath.ToSlash(filepath.Join(base, entry.Name())),
			Type: kind, Size: info.Size(), ModifiedAt: info.ModTime().UTC(),
		})
	}
	return out, nil
}

// BrowsePath lists a directory on the node's raw filesystem, starting from
// the node's home directory by default. It is used to let operators pick a
// LocalPath visually before creating a mount, so it is not scoped to any
// existing mount.
func (s *Service) BrowsePath(ctx context.Context, path string, limit int) (home, resolved, parent string, entries []entities.FileEntry, err error) {
	homeDir, homeErr := os.UserHomeDir()
	if homeErr != nil {
		homeDir = string(filepath.Separator)
	}
	if absolute, absErr := filepath.Abs(homeDir); absErr == nil {
		homeDir = absolute
	}
	if evaluated, evalErr := filepath.EvalSymlinks(homeDir); evalErr == nil {
		homeDir = evaluated
	}
	target := strings.TrimSpace(path)
	if target == "" {
		target = homeDir
	}
	absoluteTarget, absErr := filepath.Abs(target)
	if absErr != nil {
		return "", "", "", nil, fmt.Errorf("%w: invalid path", ErrInvalid)
	}
	evaluated, evalErr := filepath.EvalSymlinks(absoluteTarget)
	if evalErr != nil {
		if errors.Is(evalErr, fs.ErrNotExist) {
			return "", "", "", nil, ErrNotFound
		}
		return "", "", "", nil, evalErr
	}
	info, statErr := os.Stat(evaluated)
	if statErr != nil {
		return "", "", "", nil, statErr
	}
	if !info.IsDir() {
		return "", "", "", nil, fmt.Errorf("%w: path is not a directory", ErrInvalid)
	}
	if s.blocked(evaluated) {
		return "", "", "", nil, fmt.Errorf("%w: path is protected", ErrInvalid)
	}
	dirEntries, readErr := os.ReadDir(evaluated)
	if readErr != nil {
		return "", "", "", nil, readErr
	}
	visible := dirEntries[:0]
	for _, entry := range dirEntries {
		if isInternalPartialName(entry.Name()) || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		visible = append(visible, entry)
	}
	dirEntries = visible
	sort.Slice(dirEntries, func(i, j int) bool {
		if dirEntries[i].IsDir() != dirEntries[j].IsDir() {
			return dirEntries[i].IsDir()
		}
		return strings.ToLower(dirEntries[i].Name()) < strings.ToLower(dirEntries[j].Name())
	})
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if len(dirEntries) > limit {
		dirEntries = dirEntries[:limit]
	}
	out := make([]entities.FileEntry, 0, len(dirEntries))
	for _, entry := range dirEntries {
		entryInfo, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		fullPath := filepath.Join(evaluated, entry.Name())
		if s.blocked(fullPath) {
			continue
		}
		kind := "file"
		if entry.IsDir() {
			kind = "directory"
		} else if entryInfo.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		out = append(out, entities.FileEntry{
			Name: entry.Name(), Path: filepath.ToSlash(fullPath),
			Type: kind, Size: entryInfo.Size(), ModifiedAt: entryInfo.ModTime().UTC(),
		})
	}
	parentPath := filepath.Dir(evaluated)
	if parentPath == evaluated {
		parentPath = ""
	}
	return homeDir, evaluated, parentPath, out, nil
}

func (s *Service) blocked(path string) bool {
	for _, forbidden := range s.forbiddenRoots {
		if within(path, forbidden) || within(forbidden, path) {
			return true
		}
	}
	return false
}

func (s *Service) Metadata(ctx context.Context, mountID, relative string) (entities.FileEntry, error) {
	_, resolved, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return entities.FileEntry{}, err
	}
	info, err := os.Stat(resolved)
	if errors.Is(err, fs.ErrNotExist) {
		return entities.FileEntry{}, ErrNotFound
	}
	if err != nil {
		return entities.FileEntry{}, err
	}
	kind := "file"
	if info.IsDir() {
		kind = "directory"
	}
	return entities.FileEntry{Name: info.Name(), Path: cleanRelative(relative), Type: kind, Size: info.Size(), ModifiedAt: info.ModTime().UTC()}, nil
}

func (s *Service) Manifest(ctx context.Context, mountID, relative string) ([]entities.FileEntry, error) {
	_, root, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() {
		return []entities.FileEntry{{
			Name: rootInfo.Name(), Path: ".", Type: "file", Size: rootInfo.Size(),
			ModifiedAt: rootInfo.ModTime().UTC(),
		}}, nil
	}
	items := make([]entities.FileEntry, 0)
	err = filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relativePath, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		if relativePath == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlinks are not included in manifests", ErrInvalid)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		itemType := "file"
		if entry.IsDir() {
			itemType = "directory"
		}
		items = append(items, entities.FileEntry{
			Name: entry.Name(), Path: filepath.ToSlash(relativePath), Type: itemType,
			Size: info.Size(), ModifiedAt: info.ModTime().UTC(),
		})
		return nil
	})
	return items, err
}

// ManifestPage walks a directory without retaining the complete manifest in
// memory. The total count is still calculated so callers can validate cursors.
func (s *Service) ManifestPage(ctx context.Context, mountID, relative string, after, limit int) ([]entities.FileEntry, int, error) {
	_, root, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return nil, 0, err
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return nil, 0, err
	}
	if !rootInfo.IsDir() {
		return nil, 0, ErrInvalid
	}
	if after < 0 {
		after = 0
	}
	if limit <= 0 {
		limit = 500
	}
	items := make([]entities.FileEntry, 0, limit)
	total := 0
	err = filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relativePath, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		if relativePath == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlinks are not included in manifests", ErrInvalid)
		}
		ordinal := total
		total++
		if ordinal < after || len(items) >= limit {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		itemType := "file"
		if entry.IsDir() {
			itemType = "directory"
		}
		items = append(items, entities.FileEntry{
			Name: entry.Name(), Path: filepath.ToSlash(relativePath), Type: itemType,
			Size: info.Size(), ModifiedAt: info.ModTime().UTC(),
		})
		return nil
	})
	return items, total, err
}

func (s *Service) Open(ctx context.Context, mountID, relative string) (*os.File, os.FileInfo, error) {
	_, resolved, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%w: path is not a file", ErrInvalid)
	}
	return f, info, nil
}

// Checksum calculates SHA-256 as a stream so large files are never loaded into memory.
func (s *Service) Checksum(ctx context.Context, mountID, relative string) (string, error) {
	file, _, err := s.Open(ctx, mountID, relative)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, &contextReader{ctx: ctx, reader: file}); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *Service) CreateDirectory(ctx context.Context, mountID, relative string) error {
	mount, resolved, err := s.resolve(ctx, mountID, relative, true)
	if err != nil {
		return err
	}
	if err := writable(mount); err != nil {
		return err
	}
	return os.Mkdir(resolved, 0o777)
}

func (s *Service) Delete(ctx context.Context, mountID, relative string, recursive bool) error {
	if cleanRelative(relative) == "." {
		return fmt.Errorf("%w: mount root cannot be removed", ErrInvalid)
	}
	mount, resolved, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return err
	}
	if err := writable(mount); err != nil {
		return err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return err
	}
	if info.IsDir() && !recursive {
		return os.Remove(resolved)
	}
	return os.RemoveAll(resolved)
}

func (s *Service) Move(ctx context.Context, mountID, source, destination string, overwrite bool) error {
	if cleanRelative(source) == "." {
		return fmt.Errorf("%w: mount root cannot be moved", ErrInvalid)
	}
	if cleanRelative(source) == cleanRelative(destination) {
		return fmt.Errorf("%w: source and destination are the same", ErrInvalid)
	}
	mount, src, err := s.resolve(ctx, mountID, source, false)
	if err != nil {
		return err
	}
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return err
	}
	if err := writable(mount); err != nil {
		return err
	}
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if sourceInfo.IsDir() && within(src, dst) {
		return fmt.Errorf("%w: destination cannot be inside source", ErrInvalid)
	}
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return ErrConflict
		}
		return os.Rename(src, dst)
	}

	// Do not delete an existing destination before the replacement is known to
	// succeed. A temporary sibling keeps the rollback on the same filesystem.
	if _, err := os.Lstat(dst); errors.Is(err, fs.ErrNotExist) {
		return os.Rename(src, dst)
	} else if err != nil {
		return err
	}
	backup, err := os.CreateTemp(filepath.Dir(dst), ".jolt-move-backup-*")
	if err != nil {
		return err
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupPath)
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return err
	}
	if err := os.Rename(dst, backupPath); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if restoreErr := os.Rename(backupPath, dst); restoreErr != nil {
			return fmt.Errorf("move failed: %w (also could not restore destination: %v)", err, restoreErr)
		}
		return err
	}
	return os.RemoveAll(backupPath)
}

func (s *Service) Upload(ctx context.Context, mountID, relative string, body io.Reader, overwrite bool, limiters ...ByteRateLimiter) (int64, error) {
	mount, destination, err := s.resolve(ctx, mountID, relative, true)
	if err != nil {
		return 0, err
	}
	if err := writable(mount); err != nil {
		return 0, err
	}
	if !overwrite {
		if _, err := os.Lstat(destination); err == nil {
			return 0, ErrConflict
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".jolt-*.partial")
	if err != nil {
		return 0, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if len(limiters) > 0 && limiters[0] != nil {
		body = &limitedReader{ctx: ctx, reader: body, limiter: limiters[0]}
	}
	written, copyErr := io.Copy(temp, &contextReader{ctx: ctx, reader: body})
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if copyErr != nil {
		return written, copyErr
	}
	if syncErr != nil {
		return written, syncErr
	}
	if closeErr != nil {
		return written, closeErr
	}
	if err := os.Rename(tempName, destination); err != nil {
		return written, err
	}
	return written, nil
}

func (s *Service) Copy(ctx context.Context, mountID, source, destination string, overwrite bool) (int64, error) {
	return s.CopyWithProgress(ctx, mountID, source, destination, overwrite, nil)
}

func (s *Service) CopyWithProgress(ctx context.Context, mountID, source, destination string, overwrite bool, progress func(int64, int64)) (int64, error) {
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
	info, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	if info.IsDir() {
		if within(src, dst) {
			return 0, fmt.Errorf("%w: destination cannot be inside source", ErrInvalid)
		}
		return s.copyDirectory(ctx, src, dst, overwrite, progress)
	}
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	return copyAtomic(ctx, in, dst, overwrite, info.Size(), 0, progress)
}

// CopyFileVerified hashes the temporary file while streaming and validates it
// before the atomic rename publishes or replaces the destination.
func (s *Service) CopyFileVerified(ctx context.Context, mountID, source, destination string, overwrite bool, expectedChecksum string, allowSourceChange bool, progress func(int64, int64)) (int64, string, error) {
	mount, src, err := s.resolve(ctx, mountID, source, false)
	if err != nil {
		return 0, "", err
	}
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, "", err
	}
	if err := writable(mount); err != nil {
		return 0, "", err
	}
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return 0, "", ErrConflict
		}
	}
	input, err := os.Open(src)
	if err != nil {
		return 0, "", err
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil {
		return 0, "", err
	}
	if !before.Mode().IsRegular() {
		return 0, "", fmt.Errorf("%w: source is not a regular file", ErrInvalid)
	}
	temp, err := os.CreateTemp(filepath.Dir(dst), ".jolt-*.partial")
	if err != nil {
		return 0, "", err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	hash := sha256.New()
	reader := &progressReader{ctx: ctx, reader: input, total: before.Size(), progress: progress}
	written, copyErr := io.Copy(io.MultiWriter(temp, hash), reader)
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if copyErr != nil {
		return written, "", copyErr
	}
	if syncErr != nil {
		return written, "", syncErr
	}
	if closeErr != nil {
		return written, "", closeErr
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	after, err := input.Stat()
	if err != nil {
		return written, checksum, err
	}
	if !allowSourceChange &&
		(before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
			(expectedChecksum != "" && checksum != expectedChecksum)) {
		return written, checksum, ErrSourceChanged
	}
	if overwrite {
		if info, statErr := os.Lstat(dst); statErr == nil && info.IsDir() {
			if err := os.RemoveAll(dst); err != nil {
				return written, checksum, err
			}
		}
	}
	if err := os.Rename(tempName, dst); err != nil {
		return written, checksum, err
	}
	return written, checksum, nil
}

// CopyFileResumable copies a regular file into a deterministic partial file.
// The checkpoint is the last byte count known to be synced and persisted by the
// caller; bytes beyond it are discarded after an unclean interruption.
func (s *Service) CopyFileResumable(ctx context.Context, mountID, source, destination, resumeKey string, overwrite bool, checkpoint, chunkSize int64, expectedChecksum string, allowSourceChange bool, progress func(int64, int64) error, limiters ...ByteRateLimiter) (int64, string, error) {
	mount, src, err := s.resolve(ctx, mountID, source, false)
	if err != nil {
		return 0, "", err
	}
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, "", err
	}
	if err := writable(mount); err != nil {
		return 0, "", err
	}
	if chunkSize <= 0 {
		chunkSize = 16 << 20
	}
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return 0, "", ErrConflict
		}
	}
	input, err := os.Open(src)
	if err != nil {
		return 0, "", err
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil {
		return 0, "", err
	}
	if !before.Mode().IsRegular() {
		return 0, "", fmt.Errorf("%w: source is not a regular file", ErrInvalid)
	}
	partialPath := resumablePartialPath(dst, resumeKey)
	partial, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, "", err
	}
	defer partial.Close()
	partialInfo, err := partial.Stat()
	if err != nil {
		return 0, "", err
	}
	if checkpoint < 0 || checkpoint > before.Size() || checkpoint > partialInfo.Size() {
		checkpoint = 0
	}
	if partialInfo.Size() != checkpoint {
		if err := partial.Truncate(checkpoint); err != nil {
			return 0, "", err
		}
	}
	if checkpoint > 0 {
		matches, err := matchingPrefix(input, partial, checkpoint)
		if err != nil {
			return 0, "", err
		}
		if !matches {
			checkpoint = 0
			if err := partial.Truncate(0); err != nil {
				return 0, "", err
			}
		}
	}
	if _, err := input.Seek(checkpoint, io.SeekStart); err != nil {
		return 0, "", err
	}
	if _, err := partial.Seek(checkpoint, io.SeekStart); err != nil {
		return 0, "", err
	}
	var sourceReader io.Reader = input
	if len(limiters) > 0 && limiters[0] != nil {
		sourceReader = &limitedReader{ctx: ctx, reader: input, limiter: limiters[0]}
	}
	completed := checkpoint
	buffer := make([]byte, minInt64(chunkSize, 1<<20))
	for completed < before.Size() {
		if err := ctx.Err(); err != nil {
			return completed, "", err
		}
		remaining := minInt64(chunkSize, before.Size()-completed)
		written, copyErr := io.CopyBuffer(partial, io.LimitReader(&contextReader{ctx: ctx, reader: sourceReader}, remaining), buffer)
		completed += written
		if copyErr != nil {
			return completed, "", copyErr
		}
		if written != remaining {
			return completed, "", io.ErrUnexpectedEOF
		}
		if err := partial.Sync(); err != nil {
			return completed, "", err
		}
		if progress != nil {
			if err := progress(completed, before.Size()); err != nil {
				return completed, "", err
			}
		}
	}
	after, err := input.Stat()
	if err != nil {
		return completed, "", err
	}
	if !allowSourceChange && (before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime())) {
		return completed, "", ErrSourceChanged
	}
	if _, err := partial.Seek(0, io.SeekStart); err != nil {
		return completed, "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, partial); err != nil {
		return completed, "", err
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	if !allowSourceChange && expectedChecksum != "" && checksum != expectedChecksum {
		return completed, checksum, ErrSourceChanged
	}
	if err := partial.Close(); err != nil {
		return completed, checksum, err
	}
	if overwrite {
		if info, statErr := os.Lstat(dst); statErr == nil && info.IsDir() {
			if err := os.RemoveAll(dst); err != nil {
				return completed, checksum, err
			}
		}
	}
	if err := os.Rename(partialPath, dst); err != nil {
		return completed, checksum, err
	}
	return completed, checksum, nil
}

// CopyFileResumableParallel copies bounded batches of non-overlapping source
// ranges concurrently. A batch is synced in full before the durable contiguous
// checkpoint advances, so interruption can only discard the current batch.
func (s *Service) CopyFileResumableParallel(ctx context.Context, mountID, source, destination, resumeKey string, overwrite bool, checkpoint, chunkSize int64, maxParallel int, expectedChecksum string, allowSourceChange bool, progress func(int64, int64) error, limiter ByteRateLimiter) (int64, string, error) {
	if maxParallel <= 1 {
		return s.CopyFileResumable(ctx, mountID, source, destination, resumeKey, overwrite,
			checkpoint, chunkSize, expectedChecksum, allowSourceChange, progress, limiter)
	}
	mount, src, err := s.resolve(ctx, mountID, source, false)
	if err != nil {
		return 0, "", err
	}
	_, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, "", err
	}
	if err := writable(mount); err != nil {
		return 0, "", err
	}
	if chunkSize <= 0 {
		chunkSize = 16 << 20
	}
	if maxParallel > 16 {
		maxParallel = 16
	}
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return 0, "", ErrConflict
		}
	}
	input, err := os.Open(src)
	if err != nil {
		return 0, "", err
	}
	defer input.Close()
	before, err := input.Stat()
	if err != nil {
		return 0, "", err
	}
	if !before.Mode().IsRegular() {
		return 0, "", fmt.Errorf("%w: source is not a regular file", ErrInvalid)
	}
	partialPath := resumablePartialPath(dst, resumeKey)
	partial, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, "", err
	}
	defer partial.Close()
	partialInfo, err := partial.Stat()
	if err != nil {
		return 0, "", err
	}
	if checkpoint < 0 || checkpoint > before.Size() || checkpoint > partialInfo.Size() {
		checkpoint = 0
	}
	if partialInfo.Size() != checkpoint {
		if err := partial.Truncate(checkpoint); err != nil {
			return 0, "", err
		}
	}
	if checkpoint > 0 {
		matches, matchErr := matchingPrefix(input, partial, checkpoint)
		if matchErr != nil {
			return 0, "", matchErr
		}
		if !matches {
			checkpoint = 0
			if err := partial.Truncate(0); err != nil {
				return 0, "", err
			}
		}
	}
	if err := partial.Truncate(before.Size()); err != nil {
		return checkpoint, "", err
	}
	completed := checkpoint
	for completed < before.Size() {
		batchStart := completed
		batchEnd := minInt64(before.Size(), batchStart+chunkSize*int64(maxParallel))
		type chunkRange struct{ start, end int64 }
		var ranges []chunkRange
		for start := batchStart; start < batchEnd; start += chunkSize {
			ranges = append(ranges, chunkRange{start: start, end: minInt64(batchEnd, start+chunkSize)})
		}
		batchContext, cancel := context.WithCancel(ctx)
		results := make(chan error, len(ranges))
		var progressMu sync.Mutex
		for _, current := range ranges {
			go func(current chunkRange) {
				buffer := make([]byte, minInt64(chunkSize, 1<<20))
				for offset := current.start; offset < current.end; {
					if err := batchContext.Err(); err != nil {
						results <- err
						return
					}
					want := int(minInt64(int64(len(buffer)), current.end-offset))
					count, readErr := input.ReadAt(buffer[:want], offset)
					if count > 0 {
						if limiter != nil {
							if waitErr := limiter.Wait(batchContext, int64(count)); waitErr != nil {
								results <- waitErr
								return
							}
						}
						written, writeErr := partial.WriteAt(buffer[:count], offset)
						if writeErr != nil {
							results <- writeErr
							return
						}
						if written != count {
							results <- io.ErrShortWrite
							return
						}
						offset += int64(count)
					}
					if readErr != nil && !(errors.Is(readErr, io.EOF) && offset == current.end) {
						results <- readErr
						return
					}
					if count == 0 && readErr == nil {
						results <- io.ErrNoProgress
						return
					}
				}
				progressMu.Lock()
				if progress != nil {
					if progressErr := progress(completed, before.Size()); progressErr != nil {
						progressMu.Unlock()
						results <- progressErr
						return
					}
				}
				progressMu.Unlock()
				results <- nil
			}(current)
		}
		var batchErr error
		for range ranges {
			if resultErr := <-results; resultErr != nil && batchErr == nil {
				batchErr = resultErr
				cancel()
			}
		}
		cancel()
		if batchErr != nil {
			return batchStart, "", batchErr
		}
		if err := partial.Sync(); err != nil {
			return batchStart, "", err
		}
		completed = batchEnd
		if progress != nil {
			if err := progress(completed, before.Size()); err != nil {
				return completed, "", err
			}
		}
	}
	after, err := input.Stat()
	if err != nil {
		return completed, "", err
	}
	if !allowSourceChange && (before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime())) {
		return completed, "", ErrSourceChanged
	}
	if _, err := partial.Seek(0, io.SeekStart); err != nil {
		return completed, "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, partial); err != nil {
		return completed, "", err
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	if !allowSourceChange && expectedChecksum != "" && checksum != expectedChecksum {
		return completed, checksum, ErrSourceChanged
	}
	if err := partial.Close(); err != nil {
		return completed, checksum, err
	}
	if overwrite {
		if info, statErr := os.Lstat(dst); statErr == nil && info.IsDir() {
			if err := os.RemoveAll(dst); err != nil {
				return completed, checksum, err
			}
		}
	}
	if err := os.Rename(partialPath, dst); err != nil {
		return completed, checksum, err
	}
	return completed, checksum, nil
}

// ReceiveFileResumable writes a bounded remote stream into a deterministic
// partial file. Only fully synced chunks reported through progress become
// durable checkpoints; retry truncates any bytes beyond that checkpoint.
func (s *Service) ReceiveFileResumable(ctx context.Context, mountID, destination, resumeKey string, overwrite bool, checkpoint, chunkSize, expectedSize int64, expectedChecksum string, input io.Reader, progress func(int64, int64) error, finalValidation func() error, limiters ...ByteRateLimiter) (int64, string, error) {
	mount, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, "", err
	}
	if err := writable(mount); err != nil {
		return 0, "", err
	}
	if expectedSize < 0 || checkpoint < 0 || checkpoint > expectedSize {
		return 0, "", fmt.Errorf("%w: invalid remote size or checkpoint", ErrInvalid)
	}
	if chunkSize <= 0 {
		chunkSize = 16 << 20
	}
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return 0, "", ErrConflict
		}
	}
	partialPath := resumablePartialPath(dst, resumeKey)
	partial, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, "", err
	}
	defer partial.Close()
	info, err := partial.Stat()
	if err != nil {
		return 0, "", err
	}
	if checkpoint > info.Size() {
		checkpoint = 0
	}
	if info.Size() != checkpoint {
		if err := partial.Truncate(checkpoint); err != nil {
			return 0, "", err
		}
	}
	if _, err := partial.Seek(checkpoint, io.SeekStart); err != nil {
		return 0, "", err
	}
	completed := checkpoint
	if len(limiters) > 0 && limiters[0] != nil {
		input = &limitedReader{ctx: ctx, reader: input, limiter: limiters[0]}
	}
	buffer := make([]byte, minInt64(chunkSize, 1<<20))
	for completed < expectedSize {
		if err := ctx.Err(); err != nil {
			return completed, "", err
		}
		remaining := minInt64(chunkSize, expectedSize-completed)
		written, copyErr := io.CopyBuffer(partial, io.LimitReader(&contextReader{ctx: ctx, reader: input}, remaining), buffer)
		completed += written
		if copyErr != nil {
			return completed, "", copyErr
		}
		if written != remaining {
			return completed, "", io.ErrUnexpectedEOF
		}
		if err := partial.Sync(); err != nil {
			return completed, "", err
		}
		if progress != nil {
			if err := progress(completed, expectedSize); err != nil {
				return completed, "", err
			}
		}
	}
	var trailing [1]byte
	if count, err := input.Read(trailing[:]); count != 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return completed, "", fmt.Errorf("%w: remote stream exceeded the declared size", ErrInvalid)
	}
	if finalValidation != nil {
		if err := finalValidation(); err != nil {
			return completed, "", err
		}
	}
	if _, err := partial.Seek(0, io.SeekStart); err != nil {
		return completed, "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, partial); err != nil {
		return completed, "", err
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	if expectedChecksum != "" && checksum != expectedChecksum {
		return completed, checksum, fmt.Errorf("%w: remote checksum mismatch", ErrSourceChanged)
	}
	if err := partial.Close(); err != nil {
		return completed, checksum, err
	}
	if overwrite {
		if destinationInfo, statErr := os.Lstat(dst); statErr == nil {
			if destinationInfo.IsDir() {
				return completed, checksum, ErrConflict
			}
		}
	} else if _, statErr := os.Lstat(dst); statErr == nil {
		return completed, checksum, ErrConflict
	}
	if err := os.Rename(partialPath, dst); err != nil {
		return completed, checksum, err
	}
	return completed, checksum, nil
}

// ReceiveFileResumableRanges fetches non-overlapping remote ranges concurrently.
// A checkpoint advances only after every range in its contiguous batch has been
// validated and the whole batch has been synced to disk.
func (s *Service) ReceiveFileResumableRanges(
	ctx context.Context,
	mountID, destination, resumeKey string,
	overwrite bool,
	checkpoint, chunkSize, expectedSize int64,
	maxParallel int,
	expectedChecksum string,
	fetch func(context.Context, int64, int64) (io.ReadCloser, func() error, error),
	progress func(int64, int64) error,
	limiter ByteRateLimiter,
) (int64, string, error) {
	mount, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return 0, "", err
	}
	if err := writable(mount); err != nil {
		return 0, "", err
	}
	if expectedSize < 0 || checkpoint < 0 || checkpoint > expectedSize || fetch == nil {
		return 0, "", fmt.Errorf("%w: invalid remote range transfer", ErrInvalid)
	}
	if chunkSize <= 0 {
		chunkSize = 16 << 20
	}
	if maxParallel <= 0 {
		maxParallel = 1
	}
	if maxParallel > 16 {
		return 0, "", fmt.Errorf("%w: remote range parallelism exceeds 16", ErrInvalid)
	}
	if !overwrite {
		if _, err := os.Lstat(dst); err == nil {
			return 0, "", ErrConflict
		}
	}
	partialPath := resumablePartialPath(dst, resumeKey)
	partial, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return 0, "", err
	}
	defer partial.Close()
	info, err := partial.Stat()
	if err != nil {
		return 0, "", err
	}
	if checkpoint > info.Size() {
		checkpoint = 0
	}
	if info.Size() != checkpoint {
		if err := partial.Truncate(checkpoint); err != nil {
			return 0, "", err
		}
	}
	if err := partial.Truncate(expectedSize); err != nil {
		return checkpoint, "", err
	}
	completed := checkpoint
	type byteRange struct{ start, end int64 }
	for completed < expectedSize {
		batchStart := completed
		batchEnd := minInt64(expectedSize, batchStart+chunkSize*int64(maxParallel))
		ranges := make([]byteRange, 0, maxParallel)
		for start := batchStart; start < batchEnd; start += chunkSize {
			ranges = append(ranges, byteRange{start: start, end: minInt64(batchEnd, start+chunkSize) - 1})
		}
		batchContext, cancel := context.WithCancel(ctx)
		results := make(chan error, len(ranges))
		for _, current := range ranges {
			go func(current byteRange) {
				input, validate, fetchErr := fetch(batchContext, current.start, current.end)
				if fetchErr != nil {
					results <- fetchErr
					return
				}
				defer input.Close()
				reader := io.Reader(&contextReader{ctx: batchContext, reader: input})
				if limiter != nil {
					reader = &limitedReader{ctx: batchContext, reader: reader, limiter: limiter}
				}
				offset := current.start
				buffer := make([]byte, minInt64(chunkSize, 1<<20))
				for offset <= current.end {
					want := int(minInt64(int64(len(buffer)), current.end-offset+1))
					count, readErr := io.ReadFull(reader, buffer[:want])
					if count > 0 {
						written, writeErr := partial.WriteAt(buffer[:count], offset)
						if writeErr != nil {
							results <- writeErr
							return
						}
						if written != count {
							results <- io.ErrShortWrite
							return
						}
						offset += int64(count)
					}
					if readErr != nil {
						results <- readErr
						return
					}
				}
				var trailing [1]byte
				if count, readErr := input.Read(trailing[:]); count != 0 ||
					(readErr != nil && !errors.Is(readErr, io.EOF)) {
					results <- fmt.Errorf("%w: remote range exceeded its declared size", ErrInvalid)
					return
				}
				if validate != nil {
					if validateErr := validate(); validateErr != nil {
						results <- validateErr
						return
					}
				}
				results <- nil
			}(current)
		}
		var batchErr error
		for range ranges {
			if resultErr := <-results; resultErr != nil && batchErr == nil {
				batchErr = resultErr
				cancel()
			}
		}
		cancel()
		if batchErr != nil {
			return batchStart, "", batchErr
		}
		if err := partial.Sync(); err != nil {
			return batchStart, "", err
		}
		completed = batchEnd
		if progress != nil {
			if err := progress(completed, expectedSize); err != nil {
				return completed, "", err
			}
		}
	}
	if _, err := partial.Seek(0, io.SeekStart); err != nil {
		return completed, "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, partial); err != nil {
		return completed, "", err
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	if expectedChecksum != "" && checksum != expectedChecksum {
		return completed, checksum, fmt.Errorf("%w: remote checksum mismatch", ErrSourceChanged)
	}
	if err := partial.Close(); err != nil {
		return completed, checksum, err
	}
	if overwrite {
		if destinationInfo, statErr := os.Lstat(dst); statErr == nil && destinationInfo.IsDir() {
			return completed, checksum, ErrConflict
		}
	} else if _, statErr := os.Lstat(dst); statErr == nil {
		return completed, checksum, ErrConflict
	}
	if err := os.Rename(partialPath, dst); err != nil {
		return completed, checksum, err
	}
	return completed, checksum, nil
}

func (s *Service) CleanupResumablePartial(ctx context.Context, mountID, destination, resumeKey string) error {
	mount, dst, err := s.resolve(ctx, mountID, destination, true)
	if err != nil {
		return err
	}
	if err := writable(mount); err != nil {
		return err
	}
	err = os.Remove(resumablePartialPath(dst, resumeKey))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func resumablePartialPath(destination, resumeKey string) string {
	safeKey := strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			return character
		}
		return '-'
	}, resumeKey)
	return filepath.Join(filepath.Dir(destination), ".jolt-"+safeKey+".partial")
}

func matchingPrefix(source, partial *os.File, size int64) (bool, error) {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if _, err := partial.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	sourceHash, partialHash := sha256.New(), sha256.New()
	if _, err := io.CopyN(sourceHash, source, size); err != nil {
		return false, err
	}
	if _, err := io.CopyN(partialHash, partial, size); err != nil {
		return false, err
	}
	return string(sourceHash.Sum(nil)) == string(partialHash.Sum(nil)), nil
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func (s *Service) copyDirectory(ctx context.Context, source, destination string, overwrite bool, progress func(int64, int64)) (int64, error) {
	if _, err := os.Lstat(destination); err == nil && !overwrite {
		return 0, ErrConflict
	}
	var expected int64
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			expected += info.Size()
		}
		return nil
	}); err != nil {
		return 0, err
	}
	if progress != nil {
		progress(0, expected)
	}
	var completed int64
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o777)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlinks are not copied", ErrInvalid)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		n, copyErr := copyAtomic(ctx, in, target, overwrite, expected, completed, progress)
		closeErr := in.Close()
		completed += n
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	return completed, err
}

func copyAtomic(ctx context.Context, source io.Reader, destination string, overwrite bool, total, offset int64, progress func(int64, int64)) (int64, error) {
	if !overwrite {
		if _, err := os.Lstat(destination); err == nil {
			return 0, ErrConflict
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".jolt-*.partial")
	if err != nil {
		return 0, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	reader := &progressReader{ctx: ctx, reader: source, total: total, offset: offset, progress: progress}
	written, copyErr := io.Copy(temp, reader)
	syncErr := temp.Sync()
	closeErr := temp.Close()
	if copyErr != nil {
		return written, copyErr
	}
	if syncErr != nil {
		return written, syncErr
	}
	if closeErr != nil {
		return written, closeErr
	}
	if overwrite {
		if info, statErr := os.Lstat(destination); statErr == nil && info.IsDir() {
			if err := os.RemoveAll(destination); err != nil {
				return written, err
			}
		}
	}
	if err := os.Rename(tempName, destination); err != nil {
		return written, err
	}
	return written, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

type progressReader struct {
	ctx       context.Context
	reader    io.Reader
	total     int64
	offset    int64
	completed int64
	progress  func(int64, int64)
}

func (r *progressReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(buffer)
	r.completed += int64(n)
	if n > 0 && r.progress != nil {
		r.progress(r.offset+r.completed, r.total)
	}
	return n, err
}

func (s *Service) resolve(ctx context.Context, mountID, relative string, allowMissing bool) (entities.Mount, string, error) {
	mount, err := s.GetMount(ctx, mountID)
	if err != nil {
		return mount, "", err
	}
	if !mount.Enabled {
		return mount, "", ErrDisabled
	}
	clean := cleanRelative(relative)
	if filepath.IsAbs(relative) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return mount, "", ErrTraversal
	}
	if isInternalPartialName(filepath.Base(clean)) {
		return mount, "", ErrNotFound
	}
	root, err := filepath.EvalSymlinks(mount.LocalPath)
	if err != nil {
		return mount, "", err
	}
	candidate := filepath.Join(root, clean)
	check := candidate
	if allowMissing {
		check = filepath.Dir(candidate)
	}
	evaluated, err := filepath.EvalSymlinks(check)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return mount, "", ErrNotFound
		}
		return mount, "", err
	}
	if !within(root, evaluated) {
		return mount, "", ErrTraversal
	}
	if !allowMissing {
		candidate = evaluated
	}
	return mount, candidate, nil
}

func isInternalPartialName(name string) bool {
	return strings.HasPrefix(name, ".jolt-job_") && strings.HasSuffix(name, ".partial")
}

func within(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func cleanRelative(path string) string {
	path = filepath.FromSlash(strings.TrimSpace(path))
	if path == "" {
		return "."
	}
	return filepath.Clean(path)
}

func writable(m entities.Mount) error {
	if m.Mode != "read_write" {
		return ErrReadOnly
	}
	if !m.Writable {
		return fmt.Errorf("%w: filesystem permissions deny writes", ErrReadOnly)
	}
	return nil
}

func diagnose(m *entities.Mount) {
	info, err := os.Stat(m.LocalPath)
	if err != nil {
		m.State, m.Readable, m.Writable = "unavailable", false, false
		return
	}
	m.ModeBits = info.Mode().Perm().String()
	if !info.IsDir() {
		m.State, m.Readable, m.Writable = "degraded", false, false
		return
	}
	dir, err := os.Open(m.LocalPath)
	if err == nil {
		_, err = dir.Readdirnames(1)
		dir.Close()
	}
	m.Readable = err == nil || errors.Is(err, io.EOF)
	m.Writable = false
	if m.Mode == "read_write" {
		f, createErr := os.CreateTemp(m.LocalPath, ".jolt-permission-check-*")
		if createErr == nil {
			name := f.Name()
			f.Close()
			m.Writable = os.Remove(name) == nil
		}
	}
	if !m.Readable || (m.Mode == "read_write" && !m.Writable) {
		m.State = "degraded"
	} else {
		m.State = "available"
	}
}

func newID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func NewID(prefix string) string { return newID(prefix) }
