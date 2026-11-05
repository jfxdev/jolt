package filesystem

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// ManifestFiltered returns only readable entries and counts omitted roots. A
// denied directory counts once without traversing its hidden descendants.
// Callers must surface omissions and authorize final destinations separately;
// this internal primitive does not enable filtered jobs.
func (s *Service) ManifestFiltered(ctx context.Context, mountID, relative string, filter *AccessFilter) ([]entities.FileEntry, int, error) {
	if filter == nil || filter.context == nil {
		return nil, 0, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	mount, root, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return nil, 0, err
	}
	rootInfo, err := safeStat(root)
	if err != nil {
		return nil, 0, err
	}
	if !rootInfo.IsDir() && !rootInfo.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%w: unsupported manifest entry", ErrInvalid)
	}
	if err := filter.checkRoot(cleanRelativeSlash(relative), rootInfo); err != nil {
		return nil, 0, err
	}
	if !rootInfo.IsDir() {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		return []entities.FileEntry{{Name: rootInfo.Name(), Path: ".", Type: "file", Size: rootInfo.Size(), ModifiedAt: rootInfo.ModTime().UTC()}}, 0, nil
	}
	items := make([]entities.FileEntry, 0)
	omitted := 0
	err = safeWalkDirStreaming(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if current == root {
			currentRoot, err := entry.Info()
			if err != nil {
				return err
			}
			before, beforeOK := rootInfo.(pathInfo)
			after, afterOK := currentRoot.(pathInfo)
			if !currentRoot.IsDir() || !beforeOK || !afterOK || before.stat.Dev != after.stat.Dev || before.stat.Ino != after.stat.Ino {
				return ErrSourceChanged
			}
			return nil
		}
		if hiddenName(mount, entry.Name()) {
			omitted++
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := safeLstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || entry.IsDir() != info.IsDir() {
			return fmt.Errorf("%w: unsupported or changed manifest entry", ErrInvalid)
		}
		mountPath, err := filepath.Rel(mount.LocalPath, current)
		if err != nil || mountPath == ".." || strings.HasPrefix(mountPath, ".."+string(filepath.Separator)) {
			return ErrInvalid
		}
		if err := filter.checkRoot(filepath.ToSlash(mountPath), info); err != nil {
			if errors.Is(err, ErrFilteredHidden) || errors.Is(err, ErrFilteredBlocked) {
				omitted++
				if info.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return err
		}
		decision := filter.decide(filepath.ToSlash(mountPath), info)
		if !decision.visible || info.IsDir() && !decision.traversable || info.Mode().IsRegular() && !decision.readable {
			omitted++
			if info.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		entryPath, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		}
		items = append(items, entities.FileEntry{Name: info.Name(), Path: filepath.ToSlash(entryPath), Type: kind, Size: info.Size(), ModifiedAt: info.ModTime().UTC()})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items, omitted, nil
}
