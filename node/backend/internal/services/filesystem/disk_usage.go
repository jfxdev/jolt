package filesystem

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
	"golang.org/x/sys/unix"
)

type DiskUsageOptions struct {
	MaxEntries int
}

type DiskUsageResult struct {
	Path            string               `json:"path"`
	TotalBytes      int64                `json:"total_bytes"`
	Entries         []entities.FileEntry `json:"entries"`
	Scanned         int                  `json:"scanned"`
	ReadErrors      int                  `json:"read_errors"`
	Truncated       bool                 `json:"truncated"`
	TruncatedReason string               `json:"truncated_reason,omitempty"`
}

type diskUsageIdentity struct {
	device uint64
	inode  uint64
}

func (s *Service) DiskUsage(ctx context.Context, mountID, relative string, options DiskUsageOptions) (DiskUsageResult, error) {
	_, root, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return DiskUsageResult{}, err
	}
	rootInfo, err := safeStat(root)
	if err != nil {
		return DiskUsageResult{}, err
	}
	if !rootInfo.IsDir() {
		return DiskUsageResult{}, ErrInvalid
	}
	if options.MaxEntries <= 0 {
		options.MaxEntries = 1_000_000
	}

	result := DiskUsageResult{
		Path:       cleanRelativeSlash(relative),
		TotalBytes: allocatedBytes(rootInfo),
		Entries:    make([]entities.FileEntry, 0, 32),
	}
	children := make(map[string]int)
	seenFiles := make(map[diskUsageIdentity]struct{})
	stop := errors.New("stop disk usage scan")
	walkErr := safeWalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.ReadErrors++
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			result.Truncated, result.TruncatedReason = true, "timeout"
			return stop
		}
		relativePath, err := filepath.Rel(root, current)
		if err != nil {
			result.ReadErrors++
			return nil
		}
		if relativePath == "." {
			return nil
		}
		result.Scanned++
		if result.Scanned > options.MaxEntries {
			result.Truncated, result.TruncatedReason = true, "entries"
			return stop
		}
		if isInternalPartialName(entry.Name()) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			result.ReadErrors++
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return nil
		}

		usage := allocatedBytes(info)
		if identity, linked := linkedFileIdentity(info); linked {
			if _, seen := seenFiles[identity]; seen {
				usage = 0
			} else {
				seenFiles[identity] = struct{}{}
			}
		}
		result.TotalBytes += usage

		parts := strings.Split(relativePath, string(filepath.Separator))
		index, exists := children[parts[0]]
		if !exists {
			index = len(result.Entries)
			children[parts[0]] = index
			result.Entries = append(result.Entries, entities.FileEntry{})
		}
		result.Entries[index].DiskUsage += usage
		if len(parts) != 1 {
			return nil
		}
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		} else if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		result.Entries[index].Name = info.Name()
		result.Entries[index].Path = filepath.ToSlash(filepath.Join(cleanRelative(relative), info.Name()))
		result.Entries[index].Type = kind
		result.Entries[index].Size = info.Size()
		result.Entries[index].ModifiedAt = info.ModTime().UTC()
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, stop) {
		return result, walkErr
	}
	sort.SliceStable(result.Entries, func(left, right int) bool {
		if result.Entries[left].DiskUsage != result.Entries[right].DiskUsage {
			return result.Entries[left].DiskUsage > result.Entries[right].DiskUsage
		}
		return strings.ToLower(result.Entries[left].Name) < strings.ToLower(result.Entries[right].Name)
	})
	return result, nil
}

func allocatedBytes(info os.FileInfo) int64 {
	if stat, ok := info.Sys().(*unix.Stat_t); ok && stat.Blocks > 0 {
		return stat.Blocks * 512
	}
	return 0
}

func linkedFileIdentity(info os.FileInfo) (diskUsageIdentity, bool) {
	stat, ok := info.Sys().(*unix.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink < 2 {
		return diskUsageIdentity{}, false
	}
	return diskUsageIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, true
}
