package filesystem

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfxdev/jolt/backend/internal/entities"
)

// A keyset cursor survives insertion/removal before the current page. Exact
// names break case-folded ties; directory/file rank preserves the existing UI.
func entryKey(directory bool, name string) string {
	rank := "1"
	if directory {
		rank = "0"
	}
	return rank + "\x00" + strings.ToLower(name) + "\x00" + name
}

func (s *Service) ListPage(ctx context.Context, mountID, relative string, limit int, after string) (entities.FilePage, error) {
	page := entities.FilePage{Items: []entities.FileEntry{}}
	mount, resolved, err := s.resolve(ctx, mountID, relative, false)
	if err != nil {
		return page, err
	}
	if !mount.Enabled {
		return page, ErrDisabled
	}
	cursor := ""
	if after != "" {
		raw, err := base64.RawURLEncoding.DecodeString(after)
		if err != nil || len(raw) > 4096 || len(strings.Split(string(raw), "\x00")) != 3 {
			return page, fmt.Errorf("%w: invalid directory cursor", ErrInvalid)
		}
		cursor = string(raw)
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	entries, err := safeReadDir(resolved)
	if err != nil {
		return page, err
	}
	sort.Slice(entries, func(i, j int) bool {
		return entryKey(entries[i].IsDir(), entries[i].Name()) < entryKey(entries[j].IsDir(), entries[j].Name())
	})
	last := ""
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return page, err
		}
		key := entryKey(entry.IsDir(), entry.Name())
		if key <= cursor || isInternalPartialName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if len(page.Items) == limit {
			page.HasMore = true
			page.NextAfter = base64.RawURLEncoding.EncodeToString([]byte(last))
			break
		}
		kind := "file"
		if entry.IsDir() {
			kind = "directory"
		} else if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		page.Items = append(page.Items, entities.FileEntry{Name: entry.Name(), Path: filepath.ToSlash(filepath.Join(cleanRelative(relative), entry.Name())), Type: kind, Size: info.Size(), ModifiedAt: info.ModTime().UTC()})
		last = key
	}
	return page, nil
}
