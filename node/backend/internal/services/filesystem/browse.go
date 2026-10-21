package filesystem

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// ErrTruncated reports that a bounded traversal stopped before covering the
// whole subtree. It is informational: callers return the partial result and
// flag it instead of failing.
var ErrTruncated = errors.New("traversal truncated")

// ArchiveOptions bounds a streaming archive. The limits exist because the
// response is streamed: once bytes are on the wire the status code cannot be
// changed, so a runaway directory has to be refused up front rather than
// producing a truncated download that looks successful.
type ArchiveOptions struct {
	// Names restricts the archive to these direct children of the base path.
	// Empty means the whole base directory.
	Names []string
	// Compress enables Deflate. Off by default: media and archives on a NAS are
	// already compressed, and Store saturates the link instead of a CPU core.
	Compress bool
	// MaxEntries and MaxBytes cap the archive. Zero means unlimited.
	MaxEntries int
	MaxBytes   int64
	Limiter    ByteRateLimiter
}

// ArchiveResult reports what a completed archive contained.
type ArchiveResult struct {
	Entries        int
	Bytes          int64
	SkippedSymlink int
}

// ArchiveName suggests a download filename for an archive of relative.
func ArchiveName(relative string) string {
	cleaned := strings.Trim(strings.ReplaceAll(strings.TrimSpace(relative), "\\", "/"), "/")
	base := path.Base(cleaned)
	if base == "" || base == "." || base == "/" {
		base = "arquivos"
	}
	return base + ".zip"
}

// PlanArchive measures what an archive would contain without writing it, so a
// caller can reject an oversized request before any byte reaches the client.
func (s *Service) PlanArchive(ctx context.Context, mountID, relative string, options ArchiveOptions) (ArchiveResult, error) {
	roots, err := s.archiveRoots(ctx, mountID, relative, options.Names)
	if err != nil {
		return ArchiveResult{}, err
	}
	result := ArchiveResult{}
	for _, root := range roots {
		if err := walkArchive(ctx, root, func(_ string, entry fs.DirEntry, info os.FileInfo) error {
			if entry.IsDir() {
				return nil
			}
			result.Entries++
			result.Bytes += info.Size()
			if options.MaxEntries > 0 && result.Entries > options.MaxEntries {
				return fmt.Errorf("%w: a seleção excede %d arquivos", ErrInvalid, options.MaxEntries)
			}
			if options.MaxBytes > 0 && result.Bytes > options.MaxBytes {
				return fmt.Errorf("%w: a seleção excede o tamanho máximo do arquivo compactado", ErrInvalid)
			}
			return nil
		}, func() { result.SkippedSymlink++ }); err != nil {
			return ArchiveResult{}, err
		}
	}
	return result, nil
}

// Archive streams a ZIP of relative, or of the selected Names inside it, to
// writer. Symlinks are skipped and counted rather than followed: following one
// could copy data from outside the mount into a download, and failing the whole
// archive over a single link makes directories with stray links undownloadable.
func (s *Service) Archive(ctx context.Context, mountID, relative string, options ArchiveOptions, writer io.Writer) (ArchiveResult, error) {
	roots, err := s.archiveRoots(ctx, mountID, relative, options.Names)
	if err != nil {
		return ArchiveResult{}, err
	}
	archive := zip.NewWriter(writer)
	result := ArchiveResult{}
	for _, root := range roots {
		if err := s.archiveRoot(ctx, archive, root, options, &result); err != nil {
			// The partial archive is abandoned deliberately: closing it would
			// publish a valid-looking ZIP that silently lacks files.
			return result, err
		}
	}
	if err := archive.Close(); err != nil {
		return result, err
	}
	return result, nil
}

// archiveRoot adds one selected root to the archive. prefix keeps the root's
// own name in the archive so extracting a multi-selection does not scatter
// files into the current directory.
func (s *Service) archiveRoot(ctx context.Context, archive *zip.Writer, root archiveRoot,
	options ArchiveOptions, result *ArchiveResult) error {
	return walkArchive(ctx, root, func(current string, entry fs.DirEntry, info os.FileInfo) error {
		name, err := archiveEntryName(root, current, entry.IsDir())
		if err != nil {
			return err
		}
		if name == "" {
			return nil
		}
		if !entry.IsDir() {
			result.Entries++
			if options.MaxEntries > 0 && result.Entries > options.MaxEntries {
				return fmt.Errorf("%w: a seleção excede %d arquivos", ErrInvalid, options.MaxEntries)
			}
			if options.MaxBytes > 0 && result.Bytes+info.Size() > options.MaxBytes {
				return fmt.Errorf("%w: a seleção excede o tamanho máximo do arquivo compactado", ErrInvalid)
			}
		}
		header := &zip.FileHeader{Name: name, Modified: info.ModTime()}
		header.SetMode(info.Mode().Perm())
		if entry.IsDir() {
			header.Method = zip.Store
			_, err := archive.CreateHeader(header)
			return err
		}
		header.Method = zip.Store
		if options.Compress {
			header.Method = zip.Deflate
		}
		// UncompressedSize64 lets clients show a progress bar for stored
		// entries; the ZIP writer fills the rest of the data descriptor.
		header.UncompressedSize64 = uint64(info.Size())
		target, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		file, err := safeOpen(current)
		if err != nil {
			return err
		}
		defer file.Close()
		var source io.Reader = &contextReader{ctx: ctx, reader: file}
		if options.Limiter != nil {
			source = &limitedReader{ctx: ctx, reader: source, limiter: options.Limiter}
		}
		written, err := io.Copy(target, source)
		result.Bytes += written
		return err
	}, func() { result.SkippedSymlink++ })
}

type archiveRoot struct {
	// absolute is the resolved path on disk.
	absolute string
	// prefix is the directory name the root is stored under inside the archive.
	// It is empty when the archive is the directory's own contents.
	prefix string
	isDir  bool
}

// archiveRoots resolves the base directory and any explicitly selected names
// through the mount's containment checks. Each selected name is resolved on its
// own so a crafted name cannot reach outside the mount.
func (s *Service) archiveRoots(ctx context.Context, mountID, relative string, names []string) ([]archiveRoot, error) {
	_, base, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return nil, err
	}
	baseInfo, err := safeStat(base)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		if !baseInfo.IsDir() {
			return nil, fmt.Errorf("%w: only directories can be archived without a selection", ErrInvalid)
		}
		return []archiveRoot{{absolute: base, isDir: true}}, nil
	}
	roots := make([]archiveRoot, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		// Only direct children may be selected: a nested path would make the
		// archive layout ambiguous and bypass the base's own authorization.
		if name == "" || name == "." || name == ".." ||
			strings.ContainsAny(name, `/\`) {
			return nil, fmt.Errorf("%w: invalid selection %q", ErrInvalid, name)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("%w: duplicate selection %q", ErrInvalid, name)
		}
		seen[name] = struct{}{}
		_, resolved, err := s.resolve(ctx, mountID, path.Join(cleanRelativeSlash(relative), name), false)
		if err != nil {
			return nil, err
		}
		info, err := safeLstat(resolved)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: symlinks cannot be archived", ErrInvalid)
		}
		roots = append(roots, archiveRoot{absolute: resolved, prefix: name, isDir: info.IsDir()})
	}
	return roots, nil
}

// archiveEntryName maps an on-disk path to its slash-separated name inside the
// archive, returning an empty name for the synthetic root entry.
func archiveEntryName(root archiveRoot, current string, isDir bool) (string, error) {
	relative, err := filepath.Rel(root.absolute, current)
	if err != nil {
		return "", err
	}
	relative = filepath.ToSlash(relative)
	switch {
	case relative == "." && root.prefix == "":
		return "", nil
	case relative == ".":
		relative = root.prefix
	case root.prefix != "":
		relative = root.prefix + "/" + relative
	}
	if isDir {
		return relative + "/", nil
	}
	return relative, nil
}

// walkArchive walks a root, skipping symlinks and reporting each one through
// onSymlink. A single root that is itself a file is visited directly.
func walkArchive(ctx context.Context, root archiveRoot,
	visit func(string, fs.DirEntry, os.FileInfo) error, onSymlink func()) error {
	if !root.isDir {
		info, err := safeLstat(root.absolute)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			onSymlink()
			return nil
		}
		return visit(root.absolute, fs.FileInfoToDirEntry(info), info)
	}
	return safeWalkDir(root.absolute, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			onSymlink()
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			// Sockets, devices and FIFOs have no meaningful archive
			// representation and would block on read.
			return nil
		}
		if isInternalPartialName(entry.Name()) {
			// An in-flight upload or transfer checkpoint is not content.
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return visit(current, entry, info)
	})
}

// SearchOptions bounds a subtree search. Every limit is required in practice:
// an unbounded walk over a large NAS mount would pin a disk and a worker for
// minutes on a single request.
type SearchOptions struct {
	Query string
	// Type filters results: "file", "directory", or empty for both.
	Type string
	// Extensions matches the lowercase extension without the dot.
	Extensions     []string
	MinSize        int64
	MaxSize        int64
	ModifiedAfter  time.Time
	ModifiedBefore time.Time
	MaxResults     int
	// MaxEntries caps how many filesystem entries may be inspected.
	MaxEntries int
}

// SearchResult carries the matches plus why the walk stopped, so the UI can
// say "showing the first N of more" instead of implying the list is complete.
type SearchResult struct {
	Entries   []entities.FileEntry `json:"entries"`
	Scanned   int                  `json:"scanned"`
	Truncated bool                 `json:"truncated"`
	// TruncatedReason is "results", "entries" or "timeout" when Truncated.
	TruncatedReason string `json:"truncated_reason,omitempty"`
}

// Search walks the subtree under relative and returns entries whose name
// matches. Symlinks are never followed: a link back to an ancestor would make
// the walk loop, and a link out of the mount would leak paths the caller has no
// authorization for.
func (s *Service) Search(ctx context.Context, mountID, relative string, options SearchOptions) (SearchResult, error) {
	_, root, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return SearchResult{}, err
	}
	info, err := safeStat(root)
	if err != nil {
		return SearchResult{}, err
	}
	if !info.IsDir() {
		return SearchResult{}, fmt.Errorf("%w: search requires a directory", ErrInvalid)
	}
	needle := strings.ToLower(strings.TrimSpace(options.Query))
	if needle == "" && len(options.Extensions) == 0 && options.Type == "" &&
		options.MinSize <= 0 && options.MaxSize <= 0 &&
		options.ModifiedAfter.IsZero() && options.ModifiedBefore.IsZero() {
		return SearchResult{}, fmt.Errorf("%w: search requires a query or a filter", ErrInvalid)
	}
	if options.MaxResults <= 0 {
		options.MaxResults = 500
	}
	if options.MaxEntries <= 0 {
		options.MaxEntries = 200_000
	}
	extensions := make(map[string]struct{}, len(options.Extensions))
	for _, extension := range options.Extensions {
		extension = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(extension), "."))
		if extension != "" {
			extensions[extension] = struct{}{}
		}
	}

	result := SearchResult{Entries: make([]entities.FileEntry, 0, 32)}
	stop := errors.New("stop")
	walkErr := safeWalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// An unreadable subdirectory must not abort the whole search: a NAS
			// mount routinely holds directories the node cannot enter.
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			result.Truncated, result.TruncatedReason = true, "timeout"
			return stop
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if isInternalPartialName(entry.Name()) {
			return nil
		}
		relativePath, err := filepath.Rel(root, current)
		if err != nil || relativePath == "." {
			return nil
		}
		result.Scanned++
		if result.Scanned > options.MaxEntries {
			result.Truncated, result.TruncatedReason = true, "entries"
			return stop
		}
		if !matchesSearch(entry, needle, options, extensions) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if !matchesSearchInfo(info, options) {
			return nil
		}
		if len(result.Entries) >= options.MaxResults {
			result.Truncated, result.TruncatedReason = true, "results"
			return stop
		}
		itemType := "file"
		if entry.IsDir() {
			itemType = "directory"
		}
		result.Entries = append(result.Entries, entities.FileEntry{
			Name: entry.Name(), Path: filepath.ToSlash(relativePath), Type: itemType,
			Size: info.Size(), ModifiedAt: info.ModTime().UTC(),
		})
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, stop) {
		return result, walkErr
	}
	sort.SliceStable(result.Entries, func(left, right int) bool {
		return result.Entries[left].Path < result.Entries[right].Path
	})
	return result, nil
}

func matchesSearch(entry fs.DirEntry, needle string, options SearchOptions,
	extensions map[string]struct{}) bool {
	if options.Type == "file" && entry.IsDir() {
		return false
	}
	if options.Type == "directory" && !entry.IsDir() {
		return false
	}
	if needle != "" && !strings.Contains(strings.ToLower(entry.Name()), needle) {
		return false
	}
	if len(extensions) > 0 {
		if entry.IsDir() {
			return false
		}
		extension := strings.ToLower(strings.TrimPrefix(filepath.Ext(entry.Name()), "."))
		if _, ok := extensions[extension]; !ok {
			return false
		}
	}
	return true
}

func matchesSearchInfo(info os.FileInfo, options SearchOptions) bool {
	// A directory's reported size is filesystem bookkeeping, not content, so a
	// size filter must exclude directories rather than compare against it.
	if options.MinSize > 0 || options.MaxSize > 0 {
		if info.IsDir() {
			return false
		}
		if options.MinSize > 0 && info.Size() < options.MinSize {
			return false
		}
		if options.MaxSize > 0 && info.Size() > options.MaxSize {
			return false
		}
	}
	modified := info.ModTime()
	if !options.ModifiedAfter.IsZero() && modified.Before(options.ModifiedAfter) {
		return false
	}
	if !options.ModifiedBefore.IsZero() && modified.After(options.ModifiedBefore) {
		return false
	}
	return true
}

// cleanRelativeSlash normalizes a mount-relative path to slash form for joining.
func cleanRelativeSlash(relative string) string {
	cleaned := strings.Trim(strings.ReplaceAll(strings.TrimSpace(relative), "\\", "/"), "/")
	if cleaned == "" || cleaned == "." {
		return ""
	}
	return cleaned
}
