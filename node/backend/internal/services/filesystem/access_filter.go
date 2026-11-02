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
	"github.com/jfxdev/jolt/backend/internal/filetypes"
)

var (
	ErrFilteredHidden  = errors.New("entry not found")
	ErrFilteredBlocked = errors.New("entry is blocked by access policy")
)

// AccessFilter enforces a compiled policy context for a mount. A nil filter
// preserves legacy behavior; callers must only use a verified context.
type AccessFilter struct {
	context *filetypes.Filter
	base    string
}

func NewAccessFilter(context *filetypes.Filter, base string) (*AccessFilter, error) {
	if context == nil || base == "" || strings.HasPrefix(base, "/") || strings.HasSuffix(base, "/") || strings.ContainsAny(base, "\\\x00") {
		return nil, ErrInvalid
	}
	for _, part := range strings.Split(base, "/") {
		if part == "" || part == "." || part == ".." || part == "*" || part == "**" {
			return nil, ErrInvalid
		}
	}
	return &AccessFilter{context: context, base: base}, nil
}

type accessDecision struct {
	visible     bool
	blocked     bool
	readable    bool
	traversable bool
}

func (f *AccessFilter) decide(relative string, info os.FileInfo) accessDecision {
	if f == nil {
		return accessDecision{visible: true, readable: true, traversable: true}
	}
	if f.context == nil || info == nil || path.IsAbs(relative) || strings.ContainsAny(relative, "\\\x00") {
		return accessDecision{}
	}
	for _, component := range strings.Split(relative, "/") {
		if component == ".." {
			return accessDecision{}
		}
	}
	resource := f.base
	if relative != "" && relative != "." {
		resource += "/" + relative
	}
	kind := ""
	if info.IsDir() {
		kind = "directory"
	} else if info.Mode().IsRegular() {
		kind = "file"
	} else {
		return accessDecision{}
	}
	list := f.context.Evaluate(resource, "list", kind)
	if kind == "directory" {
		if list.Allowed {
			return accessDecision{visible: true, traversable: true}
		}
		return accessDecision{visible: list.Visibility == "visible", blocked: list.Visibility == "visible"}
	}
	read := f.context.Evaluate(resource, "read", kind)
	if list.Allowed && read.Allowed {
		return accessDecision{visible: true, readable: true}
	}
	// A legacy list-only rule exposes names without granting content; a
	// read-only rule permits direct access without granting directory listing.
	// Only an actual restriction carries visibility semantics for an omission.
	if list.Allowed && !read.Allowed && !read.Restricted {
		return accessDecision{visible: true, blocked: true}
	}
	if read.Allowed && !list.Allowed && !list.Restricted {
		return accessDecision{readable: true}
	}
	if !list.Allowed && list.Visibility != "visible" || !read.Allowed && read.Visibility != "visible" {
		return accessDecision{}
	}
	return accessDecision{visible: true, blocked: true, readable: false}
}

func (f *AccessFilter) checkRoot(relative string, info os.FileInfo) error {
	if f == nil {
		return nil
	}
	// A direct request must not bypass an explicitly denied parent directory.
	// Do not require an allow for every ancestor: a narrow path grant can
	// intentionally authorize a child without granting a parent listing.
	if err := f.checkAncestors(relative); err != nil {
		return err
	}
	decision := f.decide(relative, info)
	if info.IsDir() && decision.traversable || info.Mode().IsRegular() && decision.readable {
		return nil
	}
	if decision.visible {
		return ErrFilteredBlocked
	}
	return ErrFilteredHidden
}

// validateFilteredDeleteTree rejects inaccessible or non-deletable descendants
// before removal starts. External filesystem changes may still interrupt the
// operation after this preflight.
func validateFilteredDeleteTree(ctx context.Context, mount entities.Mount, root string, filter *AccessFilter) error {
	if filter == nil {
		return nil
	}
	return safeWalkDirStreaming(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(mount.LocalPath, current)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return ErrProtectedTree
		}
		relative = filepath.ToSlash(relative)
		info, err := safeLstat(current)
		if err != nil {
			return err
		}
		if err := filter.checkRoot(relative, info); err != nil {
			if current == root {
				return err
			}
			return ErrProtectedTree
		}
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		}
		resource := filter.base + "/" + relative
		if !filter.context.Evaluate(resource, "delete", kind).Allowed {
			if current == root {
				return ErrFilteredBlocked
			}
			return ErrProtectedTree
		}
		return nil
	})
}

func (f *AccessFilter) checkAncestors(relative string) error {
	if f == nil {
		return nil
	}
	if f.context == nil || path.IsAbs(relative) || strings.ContainsAny(relative, "\\\x00") {
		return ErrFilteredHidden
	}
	parts := strings.Split(relative, "/")
	if relative == "" || relative == "." {
		return nil
	}
	resource := f.base
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return ErrFilteredHidden
		}
		if f.context.Evaluate(resource, "list", "directory").Denied {
			return ErrFilteredHidden
		}
		resource += "/" + part
	}
	return nil
}

// validateFilteredMove preflights the source, every mapped destination, and an
// existing destination tree before a rename or overwrite makes any changes.
func validateFilteredMove(ctx context.Context, mount entities.Mount, source, destination string, overwrite bool, filter *AccessFilter) error {
	if filter == nil {
		return nil
	}
	relative := func(absolute string) (string, error) {
		value, err := filepath.Rel(mount.LocalPath, absolute)
		if err != nil || value == ".." || strings.HasPrefix(value, ".."+string(filepath.Separator)) {
			return "", ErrProtectedTree
		}
		return filepath.ToSlash(value), nil
	}
	walk := func(root string, visit func(string, os.FileInfo) error) error {
		return safeWalkDirStreaming(root, func(current string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			info, err := safeLstat(current)
			if err != nil {
				return err
			}
			if err := visit(current, info); err != nil {
				if current != root {
					return ErrProtectedTree
				}
				return err
			}
			return nil
		})
	}
	checkExisting := func(current string, info os.FileInfo) error {
		r, err := relative(current)
		if err != nil {
			return err
		}
		if err := filter.checkRoot(r, info); err != nil {
			return err
		}
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		}
		resource := filter.base + "/" + r
		if !filter.context.Evaluate(resource, "read", kind).Allowed || !filter.context.Evaluate(resource, "update", kind).Allowed {
			return ErrFilteredBlocked
		}
		return nil
	}
	if err := walk(source, func(current string, info os.FileInfo) error {
		if err := checkExisting(current, info); err != nil {
			return err
		}
		suffix, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		r, err := relative(filepath.Join(destination, suffix))
		if err != nil {
			return err
		}
		if err := filter.checkAncestors(r); err != nil {
			return err
		}
		kind := "file"
		if info.IsDir() {
			kind = "directory"
		}
		if !filter.context.Evaluate(filter.base+"/"+r, "create", kind).Allowed {
			return ErrFilteredBlocked
		}
		return nil
	}); err != nil {
		return err
	}
	if !overwrite {
		return nil
	}
	if _, err := safeLstat(destination); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return walk(destination, checkExisting)
}

// validateFilteredFileDestination checks the final filename, including the
// current destination when a file would be replaced. Replacing directories is
// deliberately refused until tree publication has equivalent enforcement.
func validateFilteredFileDestination(ctx context.Context, mount entities.Mount, destination string, overwrite bool, filter *AccessFilter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if filter == nil || filter.context == nil {
		return ErrInvalid
	}
	relative, err := filepath.Rel(mount.LocalPath, destination)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrInvalid
	}
	relative = filepath.ToSlash(relative)
	if err := filter.checkAncestors(relative); err != nil {
		return err
	}
	resource := filter.base + "/" + relative
	if !filter.context.Evaluate(resource, "create", "file").Allowed {
		return ErrFilteredBlocked
	}
	info, err := safeLstat(destination)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !overwrite {
		return ErrConflict
	}
	if !info.Mode().IsRegular() {
		return ErrProtectedTree
	}
	if err := filter.checkRoot(relative, info); err != nil {
		return err
	}
	if !filter.context.Evaluate(resource, "update", "file").Allowed {
		return ErrFilteredBlocked
	}
	return nil
}
